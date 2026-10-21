package otclient

import "testing"

func TestParseURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "bare host", raw: "tunnel.example.com", want: "wss://tunnel.example.com/ws"},
		{name: "https", raw: "https://tunnel.example.com", want: "wss://tunnel.example.com/ws"},
		{name: "http with port", raw: "http://localhost:18080", want: "ws://localhost:18080/ws"},
		{name: "wss custom path", raw: "wss://tunnel.example.com/custom", want: "wss://tunnel.example.com/custom"},
		{name: "ws custom path", raw: "ws://localhost:18080/socket", want: "ws://localhost:18080/socket"},
		{name: "uppercase scheme", raw: "HTTPS://tunnel.example.com", want: "wss://tunnel.example.com/ws"},
		{name: "bare host with path", raw: "localhost:18080/custom", want: "wss://localhost:18080/custom"},
		{name: "unsupported scheme", raw: "ftp://tunnel.example.com", wantErr: true},
		{name: "query", raw: "https://tunnel.example.com/ws?token=x", wantErr: true},
		{name: "fragment", raw: "https://tunnel.example.com/ws#x", wantErr: true},
		{name: "empty", raw: "", wantErr: true},
		{name: "missing host", raw: "https:///ws", wantErr: true},
		{name: "empty hostname with port", raw: "https://:443/ws", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseURL(%q) = %v, want error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseURL(%q): %v", tt.raw, err)
			}
			if got.String() != tt.want {
				t.Fatalf("ParseURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
