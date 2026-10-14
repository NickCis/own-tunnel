package httpproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/nickcis/own-tunnel/internal/registry"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Domain   string
	Registry *registry.Registry
	Logger   *slog.Logger
	TLS      *tls.Config
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	name, ok := s.tunnelName(r.Host)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		s.logRequest(r, "", http.StatusNotFound, 0, start)
		return
	}

	t, ok := s.Registry.GetHTTP(name)
	if !ok {
		// No active backend for this subdomain — same class of failure as dial errors.
		http.Error(w, "bad gateway", http.StatusBadGateway)
		s.logRequest(r, name, http.StatusBadGateway, 0, start)
		return
	}

	// ReverseProxy speaks HTTP/1.1 to the tunnel while the public side can be
	// HTTP/2 (HTTPS). Hijacking cannot do that — http.Hijacker is HTTP/1.1-only.
	status := 0
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL = &url.URL{
				Scheme:   "http",
				Host:     r.Host,
				Path:     req.URL.Path,
				RawQuery: req.URL.RawQuery,
			}
			req.Host = r.Host
		},
		Transport: &http.Transport{
			DisableCompression: true,
			// One SSH channel per request; do not pool channel conns.
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				originHost, originPort := registry.OriginFromAddr(addrFromRequest(r))
				ch, err := t.Dial(originHost, originPort)
				if err != nil {
					return nil, err
				}
				return &chanConn{Channel: ch}, nil
			},
		},
		FlushInterval: -1, // stream / WebSocket friendly
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			s.Logger.Error("http proxy error", "name", name, "err", err)
			status = http.StatusBadGateway
			http.Error(rw, "bad gateway", http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			status = resp.StatusCode
			return nil
		},
	}
	proxy.ServeHTTP(w, r)
	s.logRequest(r, name, status, 0, start)
}

// chanConn adapts an SSH channel to net.Conn for http.Transport.DialContext.
type chanConn struct {
	ssh.Channel
}

func (c *chanConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *chanConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *chanConn) SetDeadline(time.Time) error        { return nil }
func (c *chanConn) SetReadDeadline(time.Time) error    { return nil }
func (c *chanConn) SetWriteDeadline(time.Time) error   { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "ssh" }
func (dummyAddr) String() string  { return "ssh" }

func (s *Server) tunnelName(host string) (string, bool) {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	suffix := "." + strings.ToLower(s.Domain)
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	name := strings.TrimSuffix(host, suffix)
	if name == "" || strings.Contains(name, ".") {
		return "", false
	}
	return name, true
}

func (s *Server) logRequest(r *http.Request, name string, status int, bytes int64, start time.Time) {
	attrs := []any{
		"method", r.Method,
		"host", r.Host,
		"path", r.URL.RequestURI(),
		"remote", r.RemoteAddr,
		"duration_ms", time.Since(start).Milliseconds(),
	}
	if name != "" {
		attrs = append(attrs, "tunnel", name)
	}
	if status != 0 {
		attrs = append(attrs, "status", status)
	}
	if bytes != 0 {
		attrs = append(attrs, "bytes", bytes)
	}
	s.Logger.Info("http request", attrs...)
}

func addrFromRequest(r *http.Request) net.Addr {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}
	var p int
	fmt.Sscanf(port, "%d", &p)
	ip := net.ParseIP(host)
	return &net.TCPAddr{IP: ip, Port: p}
}

func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	s.Logger.Info("http listening", "addr", addr)
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) ListenAndServeTLS(ctx context.Context, addr string) error {
	if s.TLS == nil {
		return fmt.Errorf("tls config required")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	tlsLn := tls.NewListener(ln, s.TLS)
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = ln.Close()
	}()
	s.Logger.Info("https listening", "addr", addr)
	err = srv.Serve(tlsLn)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
