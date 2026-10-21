package main

import (
	"testing"

	"github.com/nickcis/own-tunnel/internal/config"
)

func TestWebsocketReservedTunnelName(t *testing.T) {
	disabled := false
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "apex host reserves nothing",
			cfg:  &config.Config{Domain: "tunnel.example.com", WebSocket: config.WebSocketConfig{Host: "tunnel.example.com"}},
			want: "",
		},
		{
			name: "subdomain reserves label",
			cfg:  &config.Config{Domain: "tunnel.example.com", WebSocket: config.WebSocketConfig{Host: "connect.tunnel.example.com"}},
			want: "connect",
		},
		{
			name: "external host reserves nothing",
			cfg:  &config.Config{Domain: "tunnel.example.com", WebSocket: config.WebSocketConfig{Host: "connect.example.net"}},
			want: "",
		},
		{
			name: "disabled websocket reserves nothing",
			cfg: &config.Config{Domain: "tunnel.example.com", WebSocket: config.WebSocketConfig{
				Enabled: &disabled,
				Host:    "connect.tunnel.example.com",
			}},
			want: "",
		},
		{
			name: "nil config",
			cfg:  nil,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := websocketReservedTunnelName(tt.cfg); got != tt.want {
				t.Fatalf("websocketReservedTunnelName() = %q, want %q", got, tt.want)
			}
		})
	}
}
