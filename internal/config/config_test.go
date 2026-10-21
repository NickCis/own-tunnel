package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsPlainPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	content := `
domain: tunnel.example.com
users:
  - name: alice
    password_hash: "plaintext"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	content := `
domain: tunnel.example.com
listen:
  ssh: ":2222"
users:
  - name: alice
    password_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen.HTTP != ":80" {
		t.Fatalf("default http: %s", cfg.Listen.HTTP)
	}
	if cfg.Auth.MaxFailures != 5 || cfg.Auth.Lockout != "15m" {
		t.Fatalf("auth defaults: %+v", cfg.Auth)
	}
	if cfg.Auth.MaxAuthTries != 6 {
		t.Fatalf("max_auth_tries default=%d want 6", cfg.Auth.MaxAuthTries)
	}
	if len(cfg.Users[0].Permissions) != 2 {
		t.Fatalf("default perms=%v", cfg.Users[0].Permissions)
	}
}

func TestLoadPermissionsAdmin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	content := `
domain: tunnel.example.com
users:
  - name: ops
    password_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    permissions: [admin]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Users[0].Permissions) != 1 || cfg.Users[0].Permissions[0] != "admin" {
		t.Fatalf("perms=%v", cfg.Users[0].Permissions)
	}
}

func TestLoadTrimsDomainAndUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	content := `
domain: "  tunnel.example.com  "
users:
  - name: "  alice  "
    password_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "tunnel.example.com" {
		t.Fatalf("domain=%q", cfg.Domain)
	}
	if cfg.Users[0].Name != "alice" {
		t.Fatalf("user=%q", cfg.Users[0].Name)
	}
}

func TestWebSocketDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	content := `
domain: tunnel.example.com
users:
  - name: alice
    password_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WebSocketEnabled() {
		t.Fatal("websocket should be enabled by default")
	}
	if cfg.WebSocket.Path != "/ws" {
		t.Fatalf("path=%q", cfg.WebSocket.Path)
	}
	if cfg.WebSocket.Host != "tunnel.example.com" {
		t.Fatalf("host=%q", cfg.WebSocket.Host)
	}
	if cfg.WebSocket.AllowHTTP {
		t.Fatal("allow_http should default to false")
	}
}

func TestWebSocketDisabledAndValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	content := `
domain: tunnel.example.com
websocket:
  enabled: false
  path: /control
  host: connect.tunnel.example.com
users:
  - name: alice
    password_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebSocketEnabled() {
		t.Fatal("websocket should be disabled")
	}
	if cfg.WebSocket.Path != "/control" || cfg.WebSocket.Host != "connect.tunnel.example.com" {
		t.Fatalf("websocket config=%+v", cfg.WebSocket)
	}

	bad := []string{
		"domain: tunnel.example.com\nwebsocket:\n  path: ws\nusers:\n  - name: a\n    password_hash: \"$2a$10$x\"\n",
		"domain: tunnel.example.com\nwebsocket:\n  path: /\nusers:\n  - name: a\n    password_hash: \"$2a$10$x\"\n",
		"domain: tunnel.example.com\nwebsocket:\n  host: https://connect.example.com\nusers:\n  - name: a\n    password_hash: \"$2a$10$x\"\n",
	}
	for i, content := range bad {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}
