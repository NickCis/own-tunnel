package wsgateway_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nickcis/own-tunnel/internal/auth"
	"github.com/nickcis/own-tunnel/internal/config"
	"github.com/nickcis/own-tunnel/internal/registry"
	"github.com/nickcis/own-tunnel/internal/sshserver"
	"github.com/nickcis/own-tunnel/internal/wsconn"
	"github.com/nickcis/own-tunnel/internal/wsgateway"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

func TestSSHOverWebSocketForwarding(t *testing.T) {
	ts, reg := newGateway(t)
	defer ts.Close()

	publisher := dialWS(t, ts, "alice", "secret")
	defer publisher.Close()

	ln, err := publisher.Listen("tcp", "app:1234")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	if _, ok := reg.Get("app", 1234); !ok {
		t.Fatal("tunnel not registered")
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Logf("publisher accept: %v", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Logf("publisher read: %v", err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("publisher got %q", buf)
			return
		}
		_, _ = conn.Write([]byte("pong"))
	}()

	consumer := dialWS(t, ts, "alice", "secret")
	defer consumer.Close()

	conn, err := consumer.Dial("tcp", "app:1234")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("consumer got %q", buf)
	}
}

func TestSSHOverWebSocketAuthFailure(t *testing.T) {
	ts, _ := newGateway(t)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := wsconn.New(ws, nil, nil, 0)
	defer c.Close()

	cfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, _, _, err := ssh.NewClientConn(c, "example.com", cfg); err == nil {
		t.Fatal("authentication unexpectedly succeeded")
	}
}

func newGateway(t *testing.T) (*httptest.Server, *registry.Registry) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	limiter := auth.NewLimiter(5, time.Minute, time.Minute)
	authenticator, err := auth.New([]config.UserConfig{{
		Name:         "alice",
		PasswordHash: string(hash),
		Permissions:  []string{"admin"},
	}}, logger, limiter)
	if err != nil {
		t.Fatal(err)
	}

	reg := registry.New()
	sshSrv := sshserver.New([]ssh.Signer{signer}, authenticator, reg, "example.com", 3, logger)
	gw := wsgateway.New(sshSrv, "/ws", logger)
	return httptest.NewServer(gw), reg
}

func dialWS(t *testing.T, ts *httptest.Server, user, password string) *ssh.Client {
	t.Helper()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := wsconn.New(ws, nil, nil, 0)

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, chans, reqs, err := ssh.NewClientConn(c, "example.com", cfg)
	if err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	return ssh.NewClient(conn, chans, reqs)
}
