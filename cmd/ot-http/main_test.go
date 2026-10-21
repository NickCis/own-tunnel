package main

import (
	"strings"
	"testing"
)

func TestWSPortEnv(t *testing.T) {
	t.Setenv("OT_PORT", "2222")
	t.Setenv("OT_WS_PORT", "")
	t.Setenv("OT_HTTP_PORT", "")
	if got := wsPortEnv(); got != "" {
		t.Fatalf("OT_PORT should be ignored, got %q", got)
	}

	t.Setenv("OT_HTTP_PORT", "8443")
	if got := wsPortEnv(); got != "8443" {
		t.Fatalf("OT_HTTP_PORT alias = %q, want 8443", got)
	}

	t.Setenv("OT_WS_PORT", "9443")
	if got := wsPortEnv(); got != "9443" {
		t.Fatalf("OT_WS_PORT precedence = %q, want 9443", got)
	}
}

func TestRejectHTTPPortOverTCP(t *testing.T) {
	a := &app{globals: &globals{}}
	tests := []struct {
		name string
		run  func() error
	}{
		{"publish", func() error { return a.cmdPublish([]string{"tcp", "demo", "80", "3000"}) }},
		{"forward", func() error { return a.cmdForward([]string{"tcp", "demo", "80"}) }},
		{"proxy", func() error { return a.cmdProxy([]string{"demo", "80"}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil || !strings.Contains(err.Error(), "port 80") {
				t.Fatalf("expected port 80 rejection, got %v", err)
			}
		})
	}
}

func TestServerURL(t *testing.T) {
	tests := []struct {
		name string
		g    globals
		want string
	}{
		{
			name: "host defaults to https 443",
			g:    globals{host: "tunnel.example.com", scheme: "https", path: "/ws"},
			want: "https://tunnel.example.com:443/ws",
		},
		{
			name: "http defaults to port 80",
			g:    globals{host: "localhost", scheme: "http", path: "/ws"},
			want: "http://localhost:80/ws",
		},
		{
			name: "ws defaults to port 80",
			g:    globals{host: "localhost", scheme: "ws", path: "/ws"},
			want: "ws://localhost:80/ws",
		},
		{
			name: "wss defaults to port 443",
			g:    globals{host: "localhost", scheme: "wss", path: "/ws"},
			want: "wss://localhost:443/ws",
		},
		{
			name: "explicit port is kept",
			g:    globals{host: "tunnel.example.com", port: "8443", scheme: "https", path: "/ws"},
			want: "https://tunnel.example.com:8443/ws",
		},
		{
			name: "user at host is stripped",
			g:    globals{host: "alice@tunnel.example.com", user: "alice", scheme: "https", path: "/ws"},
			want: "https://tunnel.example.com:443/ws",
		},
		{
			name: "url without path gets custom path",
			g:    globals{url: "https://tunnel.example.com", path: "/control"},
			want: "https://tunnel.example.com/control",
		},
		{
			name: "url path wins over custom path",
			g:    globals{url: "https://tunnel.example.com/custom", path: "/ws"},
			want: "https://tunnel.example.com/custom",
		},
		{
			name: "url user info is removed",
			g:    globals{url: "https://alice@tunnel.example.com/ws", path: "/ws"},
			want: "https://tunnel.example.com/ws",
		},
		{
			name: "bare url gets scheme",
			g:    globals{url: "tunnel.example.com", path: "/ws"},
			want: "https://tunnel.example.com/ws",
		},
		{
			name: "bracketed ipv6 host gets port",
			g:    globals{host: "[::1]", scheme: "https", path: "/ws"},
			want: "https://[::1]:443/ws",
		},
		{
			name: "host with scheme is preserved",
			g:    globals{host: "https://tunnel.example.com", path: "/ws"},
			want: "https://tunnel.example.com/ws",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.g.serverURL(); got != tt.want {
				t.Fatalf("serverURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveHostUser(t *testing.T) {
	tests := []struct {
		name     string
		g        globals
		wantUser string
	}{
		{"user at host", globals{host: "alice@tunnel.example.com"}, "alice"},
		{"user in url", globals{url: "https://alice@tunnel.example.com/ws"}, "alice"},
		{"user in bare url", globals{url: "alice@tunnel.example.com"}, "alice"},
		{"explicit user wins", globals{host: "alice@tunnel.example.com", user: "bob"}, "bob"},
		{"no user", globals{host: "tunnel.example.com"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.g.resolveHostUser()
			if tt.g.user != tt.wantUser {
				t.Fatalf("user = %q, want %q", tt.g.user, tt.wantUser)
			}
		})
	}
}
