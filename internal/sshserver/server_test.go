package sshserver

import (
	"strings"
	"testing"

	"github.com/nickcis/own-tunnel/internal/registry"
)

func TestFormatTunnelMessageHTTPTLS(t *testing.T) {
	tun := &registry.Tunnel{Name: "app", Port: 80, Kind: registry.KindHTTP}

	withTLS := (&Server{Domain: "tunnel.example.com", HasTLS: true}).formatTunnelMessage(tun, false)
	if !strings.Contains(withTLS, "https://app.tunnel.example.com") {
		t.Fatalf("missing https URL: %q", withTLS)
	}

	withoutTLS := (&Server{Domain: "tunnel.example.com"}).formatTunnelMessage(tun, false)
	if strings.Contains(withoutTLS, "https://") {
		t.Fatalf("advertised https without TLS configured: %q", withoutTLS)
	}
}

func TestFormatTunnelMessageTCP(t *testing.T) {
	tun := &registry.Tunnel{Name: "db", Port: 5432, Kind: registry.KindTCP}
	msg := (&Server{Domain: "tunnel.example.com"}).formatTunnelMessage(tun, true)
	if !strings.Contains(msg, "assigned name: db") {
		t.Fatalf("missing assigned name: %q", msg)
	}
	if !strings.Contains(msg, "db:5432") {
		t.Fatalf("missing tcp endpoint: %q", msg)
	}
}
