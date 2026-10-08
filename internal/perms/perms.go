package perms

import (
	"fmt"
	"strings"
)

// Permission names used in config and checks.
type Permission string

const (
	Admin   Permission = "admin"   // implies all others
	Publish Permission = "publish" // create tunnels (-R)
	Dial    Permission = "dial"    // consume TCP tunnels (-L)
	Peers   Permission = "peers"   // list/dial other users' tunnels
	Blocks  Permission = "blocks"  // view auth block list
)

var all = []Permission{Admin, Publish, Dial, Peers, Blocks}

// aliases map config synonyms → canonical permission.
var aliases = map[string]Permission{
	"admin": Admin,

	"publish":          Publish,
	"remote-forward":   Publish,
	"remote-forwarding": Publish,
	"-r":               Publish,

	"dial":             Dial,
	"local-forward":    Dial,
	"local-forwarding": Dial,
	"-l":               Dial,

	"peers":  Peers,
	"all":    Peers,
	"global": Peers,

	"blocks":     Blocks,
	"block-list": Blocks,
	"blocklist":  Blocks,
	"bans":       Blocks,
}

// Set is a set of permissions for one user.
type Set map[Permission]struct{}

// Default is applied when a user omits permissions in config.
func Default() Set {
	return Set{
		Publish: {},
		Dial:    {},
	}
}

// Parse builds a Set from config strings. Empty/nil → Default().
func Parse(raw []string) (Set, error) {
	if len(raw) == 0 {
		return Default(), nil
	}
	out := Set{}
	for _, item := range raw {
		key := strings.ToLower(strings.TrimSpace(item))
		if key == "" {
			continue
		}
		p, ok := aliases[key]
		if !ok {
			return nil, fmt.Errorf("unknown permission %q (want admin, publish, dial, peers, blocks)", item)
		}
		out[p] = struct{}{}
	}
	if len(out) == 0 {
		return Default(), nil
	}
	return out, nil
}

// Has reports whether p is granted (admin grants everything).
func (s Set) Has(p Permission) bool {
	if s == nil {
		return false
	}
	if _, ok := s[Admin]; ok {
		return true
	}
	_, ok := s[p]
	return ok
}

// List returns canonical permission names present (admin expands visually as itself only).
func (s Set) List() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(all))
	for _, p := range all {
		if _, ok := s[p]; ok {
			out = append(out, string(p))
		}
	}
	return out
}
