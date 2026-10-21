package httpproxy

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nickcis/own-tunnel/internal/registry"
)

func TestControlEndpointRouting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := registry.New()
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	s := &Server{
		Domain:         "example.com",
		Registry:       reg,
		Logger:         logger,
		ControlPath:    "/ws",
		ControlHandler: handler,
	}

	tests := []struct {
		name        string
		url         string
		wantStatus  int
		wantControl bool
	}{
		{"apex control path", "http://example.com/ws", http.StatusNoContent, true},
		{"apex other path", "http://example.com/other", http.StatusNotFound, false},
		{"tunnel host control path", "http://app.example.com/ws", http.StatusBadGateway, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.url, nil))
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if called != tt.wantControl {
				t.Fatalf("control handler called = %v, want %v", called, tt.wantControl)
			}
		})
	}
}

func TestControlEndpointRequiresTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	called := false
	s := &Server{
		Domain:            "example.com",
		Registry:          registry.New(),
		Logger:            logger,
		ControlPath:       "/ws",
		ControlRequireTLS: true,
		ControlHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}),
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/ws", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("plain HTTP status = %d, want 404", rec.Code)
	}
	if called {
		t.Fatal("control handler called over plain HTTP")
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/ws", nil)
	req.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if !called {
		t.Fatal("control handler not called over TLS")
	}
}
