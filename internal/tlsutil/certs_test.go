package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nickcis/own-tunnel/internal/config"
)

func writeTestCert(t *testing.T, dir, name string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{name, "*." + name},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "fullchain.pem")
	keyPath = filepath.Join(dir, "privkey.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	_ = certFile.Close()

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		t.Fatal(err)
	}
	_ = keyFile.Close()
	return certPath, keyPath
}

func TestManagerReloadsOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCert(t, dir, "t.wss.ar", time.Now().Add(24*time.Hour))

	mgr, err := NewManager(config.TLSConfig{Cert: certPath, Key: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	first, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "foo.t.wss.ar"})
	if err != nil {
		t.Fatal(err)
	}

	// Ensure mtime can move forward on coarse filesystems.
	time.Sleep(10 * time.Millisecond)
	certPath, keyPath = writeTestCert(t, dir, "t.wss.ar", time.Now().Add(48*time.Hour))
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, future, future); err != nil {
		t.Fatal(err)
	}

	second, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "foo.t.wss.ar"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("expected a new certificate pointer after file replace")
	}
	if len(second.Certificate) == 0 {
		t.Fatal("empty reloaded certificate")
	}
}
