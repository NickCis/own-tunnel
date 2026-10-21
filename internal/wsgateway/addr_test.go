package wsgateway

import (
	"net/http/httptest"
	"testing"
)

func TestRemoteAddrReportsWebSocketAndRealIP(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/ws", nil)
	r.RemoteAddr = "192.0.2.10:12345"

	got := remoteAddr(r)
	if got.Network() != "ws" {
		t.Fatalf("network = %q, want ws", got.Network())
	}
	if got.String() != "192.0.2.10:12345" {
		t.Fatalf("address = %q, want 192.0.2.10:12345", got.String())
	}
}
