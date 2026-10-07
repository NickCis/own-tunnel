package auth

import (
	"net"
	"sort"
	"sync"
	"time"
)

// Limiter implements fail2ban-style per-IP auth throttling:
// after MaxFailures failed attempts within Window, the IP is locked out for Lockout.
type Limiter struct {
	MaxFailures int
	Window      time.Duration
	Lockout     time.Duration

	mu   sync.Mutex
	byIP map[string]*ipState
}

type ipState struct {
	failures    []time.Time
	lockedUntil time.Time
}

func NewLimiter(maxFailures int, window, lockout time.Duration) *Limiter {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	if lockout <= 0 {
		lockout = 15 * time.Minute
	}
	return &Limiter{
		MaxFailures: maxFailures,
		Window:      window,
		Lockout:     lockout,
		byIP:        make(map[string]*ipState),
	}
}

// Allow reports whether peerAddr may attempt authentication.
func (l *Limiter) Allow(peerAddr string) bool {
	if l == nil {
		return true
	}
	ip := peerIP(peerAddr)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.byIP[ip]
	if st == nil {
		return true
	}
	if now.Before(st.lockedUntil) {
		return false
	}
	// Lockout expired; prune stale failures.
	st.failures = pruneFailures(st.failures, now.Add(-l.Window))
	if len(st.failures) == 0 && st.lockedUntil.IsZero() {
		delete(l.byIP, ip)
	}
	return true
}

// Fail records a failed auth attempt for peerAddr.
func (l *Limiter) Fail(peerAddr string) {
	if l == nil {
		return
	}
	ip := peerIP(peerAddr)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	st := l.byIP[ip]
	if st == nil {
		st = &ipState{}
		l.byIP[ip] = st
	}
	st.failures = append(pruneFailures(st.failures, now.Add(-l.Window)), now)
	if len(st.failures) >= l.MaxFailures {
		st.lockedUntil = now.Add(l.Lockout)
		st.failures = nil
	}
}

// Success clears failure state for peerAddr after a successful login.
func (l *Limiter) Success(peerAddr string) {
	if l == nil {
		return
	}
	ip := peerIP(peerAddr)
	l.mu.Lock()
	delete(l.byIP, ip)
	l.mu.Unlock()
}

// BlockedIP is a currently locked-out source address.
type BlockedIP struct {
	IP          string
	LockedUntil time.Time
	Remaining   time.Duration
}

// Blocked returns IPs that are currently locked out, sorted by IP.
// Expired entries are pruned as a side effect.
func (l *Limiter) Blocked() []BlockedIP {
	if l == nil {
		return nil
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]BlockedIP, 0)
	for ip, st := range l.byIP {
		if now.Before(st.lockedUntil) {
			out = append(out, BlockedIP{
				IP:          ip,
				LockedUntil: st.lockedUntil,
				Remaining:   st.lockedUntil.Sub(now).Round(time.Second),
			})
			continue
		}
		// Expired lockout — prune if nothing else to keep.
		st.failures = pruneFailures(st.failures, now.Add(-l.Window))
		if len(st.failures) == 0 {
			delete(l.byIP, ip)
		} else {
			st.lockedUntil = time.Time{}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func pruneFailures(in []time.Time, cutoff time.Time) []time.Time {
	out := in[:0]
	for _, t := range in {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func peerIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
