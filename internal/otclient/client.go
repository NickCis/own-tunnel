// Package otclient is the SSH-over-WebSocket client used by cmd/ot-http.
package otclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nickcis/own-tunnel/internal/wsconn"
	"golang.org/x/crypto/ssh"
)

const defaultTimeout = 20 * time.Second

type Config struct {
	URL             string
	User            string
	Auth            []ssh.AuthMethod
	HostKeyCallback ssh.HostKeyCallback
	InsecureTLS     bool
	Timeout         time.Duration
	Keepalive       time.Duration
}

type Client struct {
	SSH *ssh.Client
	WS  *wsconn.Conn
}

// ParseURL accepts an http(s), ws(s), or bare host URL and returns a WebSocket
// URL. A bare host defaults to https and the /ws path.
func ParseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("server URL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q (want http, https, ws, or wss)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("server URL is missing a host")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws"
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("server URL must not contain a query or fragment")
	}
	return u, nil
}

// DialRaw opens the WebSocket connection without performing SSH authentication.
func DialRaw(ctx context.Context, cfg Config) (*wsconn.Conn, *url.URL, error) {
	u, err := ParseURL(cfg.URL)
	if err != nil {
		return nil, nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
		Proxy:            http.ProxyFromEnvironment,
	}
	if u.Scheme == "wss" {
		dialer.TLSClientConfig = &tls.Config{
			ServerName:         u.Hostname(),
			InsecureSkipVerify: cfg.InsecureTLS,
			MinVersion:         tls.VersionTLS12,
		}
	}

	ws, resp, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		if resp != nil {
			return nil, nil, fmt.Errorf("websocket dial %s: %w (HTTP %s)", u.Redacted(), err, resp.Status)
		}
		return nil, nil, fmt.Errorf("websocket dial %s: %w", u.Redacted(), err)
	}
	return wsconn.New(ws, nil, addrFromURL(u), cfg.Keepalive), u, nil
}

func addrFromURL(u *url.URL) net.Addr {
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return wsAddr{network: "tcp", address: u.Host}
	}
	if ip := net.ParseIP(host); ip != nil {
		p, _ := strconv.Atoi(port)
		return &net.TCPAddr{IP: ip, Port: p}
	}
	return wsAddr{network: "tcp", address: net.JoinHostPort(host, port)}
}

type wsAddr struct {
	network string
	address string
}

func (a wsAddr) Network() string { return a.network }
func (a wsAddr) String() string  { return a.address }

// Dial opens the WebSocket and authenticates the SSH connection.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.HostKeyCallback == nil {
		return nil, fmt.Errorf("host key callback is required")
	}
	if len(cfg.Auth) == 0 {
		return nil, fmt.Errorf("no SSH authentication method configured")
	}

	raw, u, err := DialRaw(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// The SSH handshake may pause for an interactive password prompt, so give
	// it the same login grace as the server (OpenSSH defaults to 2 minutes).
	const authGrace = 2 * time.Minute
	_ = raw.SetDeadline(time.Now().Add(authGrace))
	// Host key lookup uses conventional SSH port-22 semantics. The callback can
	// also try a configured nonstandard SSH port for known_hosts entries.
	sshConn, chans, reqs, err := ssh.NewClientConn(raw, net.JoinHostPort(u.Hostname(), "22"), &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            cfg.Auth,
		HostKeyCallback: cfg.HostKeyCallback,
		Timeout:         authGrace,
	})
	_ = raw.SetDeadline(time.Time{})
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("ssh authentication: %w", err)
	}
	return &Client{SSH: ssh.NewClient(sshConn, chans, reqs), WS: raw}, nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	if c.SSH != nil {
		_ = c.SSH.Close()
	}
	if c.WS != nil {
		return c.WS.Close()
	}
	return nil
}
