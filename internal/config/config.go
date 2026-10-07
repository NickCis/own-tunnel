package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Domain      string       `yaml:"domain"`
	Listen      ListenConfig `yaml:"listen"`
	TLS         TLSConfig    `yaml:"tls"`
	Log         LogConfig    `yaml:"log"`
	Auth        AuthConfig   `yaml:"auth"`
	HostKeysDir string      `yaml:"host_keys_dir"`
	Users       []UserConfig `yaml:"users"`
}

// AuthConfig controls SSH login throttling (fail2ban-style per IP).
type AuthConfig struct {
	MaxFailures   int    `yaml:"max_failures"`    // failures within window before lockout (default 5)
	FailureWindow string `yaml:"failure_window"`  // e.g. "15m" (default 15m)
	Lockout       string `yaml:"lockout"`         // e.g. "15m" (default 15m)
	MaxAuthTries  int    `yaml:"max_auth_tries"`  // per SSH connection (default 3)
}

type ListenConfig struct {
	SSH   string `yaml:"ssh"`
	HTTP  string `yaml:"http"`
	HTTPS string `yaml:"https"`
}

type TLSConfig struct {
	Cert    string                    `yaml:"cert"`
	Key     string                    `yaml:"key"`
	Domains map[string]DomainTLSCert  `yaml:"domains"`
}

type DomainTLSCert struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type UserConfig struct {
	Name           string   `yaml:"name"`
	PasswordHash   string   `yaml:"password_hash"`
	AuthorizedKeys []string `yaml:"authorized_keys"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	c.Domain = strings.TrimSpace(c.Domain)
	if c.Listen.SSH == "" {
		c.Listen.SSH = ":22"
	}
	if c.Listen.HTTP == "" {
		c.Listen.HTTP = ":80"
	}
	if c.Listen.HTTPS == "" {
		c.Listen.HTTPS = ":443"
	}
	if c.HostKeysDir == "" {
		c.HostKeysDir = "./host_keys"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
	if c.TLS.Domains == nil {
		c.TLS.Domains = map[string]DomainTLSCert{}
	} else {
		normalized := make(map[string]DomainTLSCert, len(c.TLS.Domains))
		for host, d := range c.TLS.Domains {
			normalized[strings.ToLower(strings.TrimSpace(host))] = d
		}
		c.TLS.Domains = normalized
	}
	if c.Auth.MaxFailures == 0 {
		c.Auth.MaxFailures = 5
	}
	if c.Auth.FailureWindow == "" {
		c.Auth.FailureWindow = "15m"
	}
	if c.Auth.Lockout == "" {
		c.Auth.Lockout = "15m"
	}
	if c.Auth.MaxAuthTries == 0 {
		c.Auth.MaxAuthTries = 3
	}
}

func (c *Config) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("at least one user is required")
	}

	seen := map[string]struct{}{}
	for i := range c.Users {
		u := &c.Users[i]
		u.Name = strings.TrimSpace(u.Name)
		if u.Name == "" {
			return fmt.Errorf("users[%d]: name is required", i)
		}
		if _, ok := seen[u.Name]; ok {
			return fmt.Errorf("duplicate user %q", u.Name)
		}
		seen[u.Name] = struct{}{}

		if u.PasswordHash != "" && !strings.HasPrefix(u.PasswordHash, "$2") {
			return fmt.Errorf("user %q: password_hash must be a bcrypt hash (plain passwords are rejected)", u.Name)
		}
		if u.PasswordHash == "" && len(u.AuthorizedKeys) == 0 {
			return fmt.Errorf("user %q: need password_hash and/or authorized_keys", u.Name)
		}
	}

	if c.Auth.MaxFailures < 1 {
		return fmt.Errorf("auth.max_failures must be >= 1")
	}
	if c.Auth.MaxAuthTries < 1 {
		return fmt.Errorf("auth.max_auth_tries must be >= 1")
	}
	if _, err := ParseDuration(c.Auth.FailureWindow); err != nil {
		return fmt.Errorf("auth.failure_window: %w", err)
	}
	if _, err := ParseDuration(c.Auth.Lockout); err != nil {
		return fmt.Errorf("auth.lockout: %w", err)
	}

	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level must be debug|info|warn|error")
	}
	switch strings.ToLower(c.Log.Format) {
	case "json", "text":
	default:
		return fmt.Errorf("log.format must be json|text")
	}

	hasDefaultTLS := c.TLS.Cert != "" && c.TLS.Key != ""
	if (c.TLS.Cert == "") != (c.TLS.Key == "") {
		return fmt.Errorf("tls.cert and tls.key must both be set or both empty")
	}
	for host, d := range c.TLS.Domains {
		if d.Cert == "" || d.Key == "" {
			return fmt.Errorf("tls.domains[%q]: cert and key are required", host)
		}
	}
	if !hasDefaultTLS && len(c.TLS.Domains) == 0 {
		// HTTPS can still start later only if certs exist; warn via validate soft-fail is not needed —
		// main will skip HTTPS if no certs configured.
	}

	return nil
}

func (c *Config) HasTLS() bool {
	if c.TLS.Cert != "" && c.TLS.Key != "" {
		return true
	}
	return len(c.TLS.Domains) > 0
}

// ParseDuration parses Go duration strings (e.g. "15m", "1h").
func ParseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	return d, nil
}

func (c *Config) AuthFailureWindow() time.Duration {
	d, _ := ParseDuration(c.Auth.FailureWindow)
	return d
}

func (c *Config) AuthLockout() time.Duration {
	d, _ := ParseDuration(c.Auth.Lockout)
	return d
}
