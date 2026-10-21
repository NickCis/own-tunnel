// Package wsconn adapts a WebSocket connection to net.Conn so it can carry an
// SSH transport. Binary WebSocket messages carry opaque bytes; text messages
// are reserved for the half-close marker used by CloseWrite.
package wsconn

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// MaxMessageSize bounds a single WebSocket message. SSH frames are much
	// smaller, so this only protects against malicious peers.
	MaxMessageSize = 4 << 20

	eofMessage = "own-tunnel-eof"

	controlWriteTimeout = time.Second
)

// Conn implements net.Conn on top of a *websocket.Conn.
//
// One goroutine may call Read while another calls Write, matching net.Conn.
// Multiple concurrent Reads are not supported (gorilla has one reader).
type Conn struct {
	ws     *websocket.Conn
	local  net.Addr
	remote net.Addr

	readBuf  []byte
	readEOF  bool
	readLock sync.Mutex

	writeMu     sync.Mutex
	writeClosed atomic.Bool
	writeOnce   sync.Once
	writeErr    error

	closeOnce sync.Once
	done      chan struct{}
	lastSeen  atomic.Int64
}

// New wraps ws. keepalive controls WebSocket ping frequency; zero disables it.
// The connection is closed if no traffic or pong is seen for three intervals.
func New(ws *websocket.Conn, local, remote net.Addr, keepalive time.Duration) *Conn {
	c := &Conn{
		ws:     ws,
		local:  local,
		remote: remote,
		done:   make(chan struct{}),
	}
	c.lastSeen.Store(time.Now().UnixNano())
	ws.SetReadLimit(MaxMessageSize)
	ws.SetPingHandler(func(data string) error {
		c.touch()
		err := ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(controlWriteTimeout))
		if errors.Is(err, websocket.ErrCloseSent) {
			return nil
		}
		return err
	})
	ws.SetPongHandler(func(string) error {
		c.touch()
		return nil
	})
	if keepalive > 0 {
		go c.keepalive(keepalive)
	}
	return c
}

func (c *Conn) touch() {
	c.lastSeen.Store(time.Now().UnixNano())
}

func (c *Conn) keepalive(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if time.Since(time.Unix(0, c.lastSeen.Load())) > 3*interval {
				_ = c.Close()
				return
			}
			if err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(controlWriteTimeout)); err != nil {
				_ = c.Close()
				return
			}
		case <-c.done:
			return
		}
	}
}

// Read reads the next binary WebSocket message. A text message containing the
// half-close marker is reported as io.EOF but does not close the write side.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.readLock.Lock()
	defer c.readLock.Unlock()

	for len(c.readBuf) == 0 {
		if c.readEOF {
			return 0, io.EOF
		}
		mt, r, err := c.ws.NextReader()
		if err != nil {
			return 0, normalizeReadError(err)
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return 0, err
		}
		c.touch()
		switch mt {
		case websocket.BinaryMessage:
			c.readBuf = data
		case websocket.TextMessage:
			if string(data) == eofMessage {
				c.readEOF = true
				return 0, io.EOF
			}
			// Ignore unknown text control messages.
		}
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write sends p as one binary WebSocket message.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.writeClosed.Load() {
		return 0, io.ErrClosedPipe
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	c.touch()
	return len(p), nil
}

// CloseWrite half-closes the write side by sending a reserved text marker.
// Reads remain available until the peer half-closes or the connection closes.
func (c *Conn) CloseWrite() error {
	c.writeOnce.Do(func() {
		c.writeClosed.Store(true)
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.writeErr = c.ws.WriteMessage(websocket.TextMessage, []byte(eofMessage))
	})
	return c.writeErr
}

// Close closes the WebSocket connection.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(controlWriteTimeout))
		_ = c.ws.Close()
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	if c.local == nil {
		return wsAddr{network: "ws", address: "local"}
	}
	return c.local
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.remote == nil {
		return wsAddr{network: "ws", address: "remote"}
	}
	return c.remote
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.ws.SetWriteDeadline(t)
}

func normalizeReadError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	if websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseNoStatusReceived,
	) {
		return io.EOF
	}
	return err
}

type wsAddr struct {
	network string
	address string
}

func (a wsAddr) Network() string { return a.network }
func (a wsAddr) String() string  { return a.address }
