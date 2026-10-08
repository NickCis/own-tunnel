package auth

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/nickcis/own-tunnel/internal/config"
	"github.com/nickcis/own-tunnel/internal/perms"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

type Authenticator struct {
	users     map[string]*userAuth
	logger    *slog.Logger
	limiter   *Limiter
	dummyHash []byte // bcrypt hash for constant-time unknown-user checks
}

type userAuth struct {
	name           string
	passwordHash   string
	authorizedKeys map[string]ssh.PublicKey // fingerprint -> key
	perms          perms.Set
}

func New(users []config.UserConfig, logger *slog.Logger, limiter *Limiter) (*Authenticator, error) {
	dummyHash, err := bcrypt.GenerateFromPassword([]byte("own-tunnel-timing-dummy"), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("dummy bcrypt: %w", err)
	}

	a := &Authenticator{
		users:     make(map[string]*userAuth, len(users)),
		logger:    logger,
		limiter:   limiter,
		dummyHash: dummyHash,
	}

	for _, u := range users {
		name := strings.TrimSpace(u.Name)
		pset, err := perms.Parse(u.Permissions)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", name, err)
		}
		ua := &userAuth{
			name:           name,
			passwordHash:   u.PasswordHash,
			authorizedKeys: make(map[string]ssh.PublicKey),
			perms:          pset,
		}
		for i, line := range u.AuthorizedKeys {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				return nil, fmt.Errorf("user %q authorized_keys[%d]: %w", name, i, err)
			}
			ua.authorizedKeys[ssh.FingerprintSHA256(pub)] = pub
		}
		a.users[name] = ua
	}
	return a, nil
}

func (a *Authenticator) peer(conn ssh.ConnMetadata) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

func (a *Authenticator) denyLocked(conn ssh.ConnMetadata, method string) (*ssh.Permissions, error) {
	a.logger.Warn("auth failed", "user", conn.User(), "method", method, "peer", a.peer(conn), "reason", "rate_limited")
	return nil, fmt.Errorf("permission denied")
}

func (a *Authenticator) Password(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	peer := a.peer(conn)
	if !a.limiter.Allow(peer) {
		return a.denyLocked(conn, "password")
	}

	u, ok := a.users[conn.User()]
	hash := a.dummyHash
	if ok && u.passwordHash != "" {
		hash = []byte(u.passwordHash)
	}

	// Always run bcrypt so unknown users / missing passwords take similar time.
	match := bcrypt.CompareHashAndPassword(hash, password) == nil && ok && u.passwordHash != ""
	if !match {
		a.limiter.Fail(peer)
		reason := "bad_password"
		if !ok || u.passwordHash == "" {
			reason = "unknown_user_or_no_password"
		}
		a.logger.Warn("auth failed", "user", conn.User(), "method", "password", "peer", peer, "reason", reason)
		return nil, fmt.Errorf("permission denied")
	}

	a.limiter.Success(peer)
	a.logger.Info("auth success", "user", conn.User(), "method", "password", "peer", peer)
	return &ssh.Permissions{
		Extensions: map[string]string{"user": conn.User()},
	}, nil
}

func (a *Authenticator) PublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	peer := a.peer(conn)
	if !a.limiter.Allow(peer) {
		return a.denyLocked(conn, "publickey")
	}

	u, ok := a.users[conn.User()]
	if !ok {
		// Unknown username counts toward lockout; wrong key for a known user does not
		// (OpenSSH clients often try several agent keys before succeeding).
		a.limiter.Fail(peer)
		a.logger.Warn("auth failed", "user", conn.User(), "method", "publickey", "peer", peer, "reason", "unknown_user")
		return nil, fmt.Errorf("permission denied")
	}
	fp := ssh.FingerprintSHA256(key)
	if _, ok := u.authorizedKeys[fp]; !ok {
		a.logger.Warn("auth failed", "user", conn.User(), "method", "publickey", "peer", peer, "reason", "key_not_authorized", "fingerprint", fp)
		return nil, fmt.Errorf("permission denied")
	}

	a.limiter.Success(peer)
	a.logger.Info("auth success", "user", conn.User(), "method", "publickey", "peer", peer, "fingerprint", fp)
	return &ssh.Permissions{
		Extensions: map[string]string{"user": conn.User()},
	}, nil
}

func (a *Authenticator) HasUser(name string) bool {
	_, ok := a.users[name]
	return ok
}

// Can reports whether user has permission p (admin implies all).
func (a *Authenticator) Can(user string, p perms.Permission) bool {
	if a == nil {
		return false
	}
	u, ok := a.users[user]
	if !ok || u.perms == nil {
		return false
	}
	return u.perms.Has(p)
}

// Perms returns a copy-like view of the user's permission set (may be nil).
func (a *Authenticator) Perms(user string) perms.Set {
	if a == nil {
		return nil
	}
	u, ok := a.users[user]
	if !ok {
		return nil
	}
	return u.perms
}

// BlockedIPs returns currently rate-limited source addresses.
func (a *Authenticator) BlockedIPs() []BlockedIP {
	if a == nil || a.limiter == nil {
		return nil
	}
	return a.limiter.Blocked()
}
