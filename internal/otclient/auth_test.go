package otclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testKey(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, priv
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	signer, _ := testKey(t)
	return signer
}

func writeTestKey(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeKnownHosts(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func remoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
}

func TestBuildHostKeyCallbackKnownHost(t *testing.T) {
	signer := testSigner(t)
	path := writeKnownHosts(t, knownhosts.Line([]string{"example.com"}, signer.PublicKey()))

	cb, err := BuildHostKeyCallback(AuthOptions{KnownHosts: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("example.com:22", remoteAddr(), signer.PublicKey()); err != nil {
		t.Fatalf("known host rejected: %v", err)
	}
}

func TestBuildHostKeyCallbackNonstandardPort(t *testing.T) {
	signer := testSigner(t)
	path := writeKnownHosts(t, knownhosts.Line([]string{"[example.com]:2222"}, signer.PublicKey()))

	cb, err := BuildHostKeyCallback(AuthOptions{KnownHosts: []string{path}, KnownHostsPort: 2222})
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("example.com:22", remoteAddr(), signer.PublicKey()); err != nil {
		t.Fatalf("nonstandard known_hosts entry rejected: %v", err)
	}
}

func TestBuildHostKeyCallbackTriesPortBeforeFailing(t *testing.T) {
	good := testSigner(t)
	bad := testSigner(t)
	path := writeKnownHosts(t,
		knownhosts.Line([]string{"example.com"}, bad.PublicKey()),
		knownhosts.Line([]string{"[example.com]:2222"}, good.PublicKey()),
	)

	cb, err := BuildHostKeyCallback(AuthOptions{KnownHosts: []string{path}, KnownHostsPort: 2222})
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("example.com:22", remoteAddr(), good.PublicKey()); err != nil {
		t.Fatalf("matching nonstandard entry rejected: %v", err)
	}
}

func TestBuildHostKeyCallbackMismatchMessage(t *testing.T) {
	known := testSigner(t)
	presented := testSigner(t)
	path := writeKnownHosts(t, knownhosts.Line([]string{"example.com"}, known.PublicKey()))

	cb, err := BuildHostKeyCallback(AuthOptions{KnownHosts: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	err = cb("example.com:22", remoteAddr(), presented.PublicKey())
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "MISMATCH") || !strings.Contains(msg, "man-in-the-middle") {
		t.Fatalf("mismatch message lacks warning: %v", err)
	}
	if strings.Contains(msg, "add it to known_hosts") {
		t.Fatalf("mismatch message encourages adding the key: %v", err)
	}
}

func TestBuildHostKeyCallbackUnknownMessage(t *testing.T) {
	signer := testSigner(t)
	path := writeKnownHosts(t)

	cb, err := BuildHostKeyCallback(AuthOptions{KnownHosts: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	err = cb("example.com:22", remoteAddr(), signer.PublicKey())
	if err == nil {
		t.Fatal("expected unknown-host error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not in known_hosts") || !strings.Contains(msg, "add it") {
		t.Fatalf("unknown-host message missing guidance: %v", err)
	}
	if strings.Contains(msg, "man-in-the-middle") {
		t.Fatalf("unknown host incorrectly reported as a mismatch: %v", err)
	}
}

func TestBuildHostKeyCallbackRevokedMessage(t *testing.T) {
	signer := testSigner(t)
	line := fmt.Sprintf("@revoked example.com %s", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
	path := writeKnownHosts(t, line)

	cb, err := BuildHostKeyCallback(AuthOptions{KnownHosts: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	err = cb("example.com:22", remoteAddr(), signer.PublicKey())
	if err == nil {
		t.Fatal("expected revoked-key error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "revoked") {
		t.Fatalf("revoked message missing: %v", err)
	}
	if strings.Contains(msg, "add it to known_hosts") {
		t.Fatalf("revoked message encourages adding the key: %v", err)
	}
}

func TestBuildHostKeyCallbackPinned(t *testing.T) {
	signer := testSigner(t)
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	cb, err := BuildHostKeyCallback(AuthOptions{HostKeyFingerprint: fp})
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("example.com:22", remoteAddr(), signer.PublicKey()); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	if err := cb("example.com:22", remoteAddr(), testSigner(t).PublicKey()); err == nil {
		t.Fatal("expected pinned-key mismatch")
	}

	lowerPrefix := "sha256:" + strings.TrimPrefix(fp, "SHA256:")
	cb, err = BuildHostKeyCallback(AuthOptions{HostKeyFingerprint: lowerPrefix})
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("example.com:22", remoteAddr(), signer.PublicKey()); err != nil {
		t.Fatalf("lowercase SHA256 prefix rejected: %v", err)
	}
}

func TestBuildHostKeyCallbackRejectsInsecureWithPin(t *testing.T) {
	_, err := BuildHostKeyCallback(AuthOptions{
		InsecureHostKey:    true,
		HostKeyFingerprint: "SHA256:abc",
	})
	if err == nil {
		t.Fatal("expected conflicting options error")
	}
}

func TestBuildAuthExplicitKeyAndPassword(t *testing.T) {
	_, priv := testKey(t)
	keyPath := writeTestKey(t, priv)

	methods, cleanup, err := BuildAuth(AuthOptions{
		KeyFiles: []string{keyPath},
		UseAgent: false,
		Password: "secret",
		Debugf:   t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	if len(methods) != 2 {
		t.Fatalf("methods=%d want 2", len(methods))
	}
}

func TestBuildAuthExplicitKeyMissing(t *testing.T) {
	_, cleanup, err := BuildAuth(AuthOptions{
		KeyFiles: []string{filepath.Join(t.TempDir(), "missing")},
		UseAgent: false,
		Password: "secret",
	})
	if err == nil {
		t.Fatal("expected missing-key error")
	}
	if cleanup != nil {
		t.Fatal("cleanup should be nil on error")
	}
}

func TestBuildAuthNoDefaultKeysPasswordOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")
	methods, cleanup, err := BuildAuth(AuthOptions{
		NoDefaultKeys: true,
		UseAgent:      false,
		Password:      "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	if len(methods) != 1 {
		t.Fatalf("methods=%d want 1", len(methods))
	}
}

func TestBuildAuthNoMethods(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")
	_, cleanup, err := BuildAuth(AuthOptions{
		NoDefaultKeys:       true,
		UseAgent:            false,
		AllowPasswordPrompt: false,
	})
	if err == nil {
		t.Fatal("expected no-methods error")
	}
	if cleanup != nil {
		t.Fatal("cleanup should be nil on error")
	}
}
