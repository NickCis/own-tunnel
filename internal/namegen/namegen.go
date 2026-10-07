package namegen

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// IsEphemeralBind reports whether the SSH bind address should be treated as
// "no custom name" (generate a random subdomain).
func IsEphemeralBind(addr string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	switch a {
	case "", "0.0.0.0", "::", "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}

// Sanitize turns a bind address into a DNS label, or returns an error.
func Sanitize(addr string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(addr))
	name = strings.ReplaceAll(name, "_", "-")
	if !labelRe.MatchString(name) {
		return "", fmt.Errorf("invalid tunnel name %q: must be a DNS label [a-z0-9-]", addr)
	}
	if len(name) > 63 {
		return "", fmt.Errorf("tunnel name too long (max 63)")
	}
	return name, nil
}

// Random returns a short random DNS label (default 8 chars).
func Random(n int) (string, error) {
	if n <= 0 {
		n = 8
	}
	var b strings.Builder
	b.Grow(n)
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[v.Int64()])
	}
	return b.String(), nil
}
