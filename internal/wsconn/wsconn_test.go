package wsconn

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestEchoLargeMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := New(ws, nil, nil, 0)
		defer c.Close()
		_, _ = io.Copy(c, c)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := New(ws, nil, nil, 0)
	defer c.Close()

	want := bytes.Repeat([]byte("own-tunnel"), 100_000) // 1 MB
	go func() {
		_, _ = c.Write(want)
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("echo payload mismatch")
	}
}

func TestHalfClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := New(ws, nil, nil, 0)
		defer c.Close()

		body, err := io.ReadAll(c)
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if string(body) != "request" {
			t.Errorf("server got %q", body)
			return
		}
		if _, err := c.Write([]byte("response")); err != nil {
			t.Errorf("server write: %v", err)
			return
		}
		_ = c.CloseWrite()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := New(ws, nil, nil, 0)
	defer c.Close()

	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "response" {
		t.Fatalf("got %q", got)
	}
}

func TestDeadlineAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := New(ws, nil, nil, 0)
		defer c.Close()
		_, _ = io.Copy(c, c)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := New(ws, nil, nil, 0)

	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("after close")); err == nil {
		t.Fatal("write after close succeeded")
	}
}
