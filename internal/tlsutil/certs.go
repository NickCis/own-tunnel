package tlsutil

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nickcis/own-tunnel/internal/config"
)

type certEntry struct {
	certPath string
	keyPath  string
	cert     *tls.Certificate
	certMod  time.Time
	keyMod   time.Time
}

// Manager selects certificates by SNI: per-domain override, then default/wildcard.
// Certificate files are re-read when their mtime changes (Let's Encrypt renewals).
type Manager struct {
	mu           sync.Mutex
	defaultEntry *certEntry
	byHost       map[string]*certEntry
}

func NewManager(cfg config.TLSConfig) (*Manager, error) {
	m := &Manager{
		byHost: make(map[string]*certEntry),
	}

	if cfg.Cert != "" && cfg.Key != "" {
		e, err := newCertEntry(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("load default tls cert: %w", err)
		}
		m.defaultEntry = e
	}

	for host, d := range cfg.Domains {
		e, err := newCertEntry(d.Cert, d.Key)
		if err != nil {
			return nil, fmt.Errorf("load tls cert for %q: %w", host, err)
		}
		m.byHost[strings.ToLower(host)] = e
	}

	if m.defaultEntry == nil && len(m.byHost) == 0 {
		return nil, fmt.Errorf("no TLS certificates configured")
	}
	return m, nil
}

func newCertEntry(certPath, keyPath string) (*certEntry, error) {
	e := &certEntry{certPath: certPath, keyPath: keyPath}
	if err := e.reload(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *certEntry) reload() error {
	certInfo, err := os.Stat(e.certPath)
	if err != nil {
		return err
	}
	keyInfo, err := os.Stat(e.keyPath)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(e.certPath, e.keyPath)
	if err != nil {
		return err
	}
	e.cert = &cert
	e.certMod = certInfo.ModTime()
	e.keyMod = keyInfo.ModTime()
	return nil
}

func (e *certEntry) get() (*tls.Certificate, error) {
	certInfo, err := os.Stat(e.certPath)
	if err != nil {
		if e.cert != nil {
			return e.cert, nil
		}
		return nil, err
	}
	keyInfo, err := os.Stat(e.keyPath)
	if err != nil {
		if e.cert != nil {
			return e.cert, nil
		}
		return nil, err
	}
	if e.cert == nil || !certInfo.ModTime().Equal(e.certMod) || !keyInfo.ModTime().Equal(e.keyMod) {
		if err := e.reload(); err != nil {
			if e.cert != nil {
				// Keep serving the previous cert if a partial renew is in flight.
				return e.cert, nil
			}
			return nil, err
		}
	}
	return e.cert, nil
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hello != nil && hello.ServerName != "" {
		if e, ok := m.byHost[strings.ToLower(hello.ServerName)]; ok {
			return e.get()
		}
	}
	if m.defaultEntry != nil {
		return m.defaultEntry.get()
	}
	for _, e := range m.byHost {
		return e.get()
	}
	name := ""
	if hello != nil {
		name = hello.ServerName
	}
	return nil, fmt.Errorf("no certificate available for %q", name)
}

func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}
