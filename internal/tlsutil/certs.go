package tlsutil

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/nickcis/own-tunnel/internal/config"
)

// Manager selects certificates by SNI: per-domain override, then default/wildcard.
type Manager struct {
	defaultCert *tls.Certificate
	byHost      map[string]*tls.Certificate
}

func NewManager(cfg config.TLSConfig) (*Manager, error) {
	m := &Manager{
		byHost: make(map[string]*tls.Certificate),
	}

	if cfg.Cert != "" && cfg.Key != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("load default tls cert: %w", err)
		}
		m.defaultCert = &cert
	}

	for host, d := range cfg.Domains {
		cert, err := tls.LoadX509KeyPair(d.Cert, d.Key)
		if err != nil {
			return nil, fmt.Errorf("load tls cert for %q: %w", host, err)
		}
		c := cert
		m.byHost[strings.ToLower(host)] = &c
	}

	if m.defaultCert == nil && len(m.byHost) == 0 {
		return nil, fmt.Errorf("no TLS certificates configured")
	}
	return m, nil
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello != nil && hello.ServerName != "" {
		if c, ok := m.byHost[strings.ToLower(hello.ServerName)]; ok {
			return c, nil
		}
	}
	if m.defaultCert != nil {
		return m.defaultCert, nil
	}
	// Fall back to any configured domain cert
	for _, c := range m.byHost {
		return c, nil
	}
	return nil, fmt.Errorf("no certificate available for %q", hello.ServerName)
}

func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}
