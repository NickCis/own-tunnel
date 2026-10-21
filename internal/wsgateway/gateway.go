// Package wsgateway exposes the SSH server over WebSocket. The WebSocket is a
// transparent byte pipe; all authentication and tunnel semantics stay in the
// existing SSH server.
package wsgateway

import (
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nickcis/own-tunnel/internal/sshserver"
	"github.com/nickcis/own-tunnel/internal/wsconn"
)

type Gateway struct {
	SSH       *sshserver.Server
	Path      string
	Logger    *slog.Logger
	Keepalive time.Duration
	upgrader  websocket.Upgrader

	mu     sync.Mutex
	conns  map[*wsconn.Conn]struct{}
	closed bool
}

func New(ssh *sshserver.Server, path string, logger *slog.Logger) *Gateway {
	if path == "" {
		path = "/ws"
	}
	return &Gateway{
		SSH:       ssh,
		Path:      path,
		Logger:    logger,
		Keepalive: 30 * time.Second,
		conns:     make(map[*wsconn.Conn]struct{}),
		upgrader: websocket.Upgrader{
			HandshakeTimeout: 10 * time.Second,
			ReadBufferSize:   32 << 10,
			WriteBufferSize:  32 << 10,
			// The endpoint speaks SSH, not browser JavaScript. Allowing any
			// origin keeps CLI clients and reverse proxies simple.
			CheckOrigin: func(*http.Request) bool { return true },
		},
	}
}

// Close stops accepting new WebSocket connections and closes active ones so
// graceful shutdown does not leave hijacked HTTP connections behind.
func (g *Gateway) Close() error {
	g.mu.Lock()
	g.closed = true
	conns := make([]*wsconn.Conn, 0, len(g.conns))
	for c := range g.conns {
		conns = append(conns, c)
	}
	g.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}

func (g *Gateway) track(c *wsconn.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	if g.conns == nil {
		g.conns = make(map[*wsconn.Conn]struct{})
	}
	g.conns[c] = struct{}{}
	return true
}

func (g *Gateway) untrack(c *wsconn.Conn) {
	g.mu.Lock()
	delete(g.conns, c)
	g.mu.Unlock()
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if g.SSH == nil {
		http.Error(w, "ssh server unavailable", http.StatusServiceUnavailable)
		return
	}
	if g.Path != "" && r.URL.Path != g.Path {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet || !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return
	}

	ws, err := g.upgrader.Upgrade(w, r, nil)
	if err != nil {
		g.Logger.Debug("websocket upgrade failed", "peer", r.RemoteAddr, "err", err)
		return
	}

	remote := remoteAddr(r)
	local := wsAddr{network: "ws", address: r.Host}
	conn := wsconn.New(ws, local, remote, g.Keepalive)
	if !g.track(conn) {
		_ = conn.Close()
		return
	}
	defer g.untrack(conn)

	g.Logger.Debug("websocket ssh opened", "peer", remote.String())
	g.SSH.ServeConn(conn)
	g.Logger.Debug("websocket ssh closed", "peer", remote.String())
}

func remoteAddr(r *http.Request) net.Addr {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			p, _ := strconv.Atoi(port)
			// Keep the real TCP address (auth lockout uses String()) but
			// report the transport so logs can distinguish SSH over TCP vs WS.
			return transportAddr{&net.TCPAddr{IP: ip, Port: p}}
		}
	}
	return wsAddr{network: "ws", address: r.RemoteAddr}
}

type transportAddr struct {
	net.Addr
}

func (transportAddr) Network() string { return "ws" }

type wsAddr struct {
	network string
	address string
}

func (a wsAddr) Network() string { return a.network }
func (a wsAddr) String() string  { return a.address }
