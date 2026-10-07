package auth

import (
	"testing"
	"time"
)

func TestLimiterLockoutAndSuccess(t *testing.T) {
	l := NewLimiter(3, time.Minute, time.Minute)
	peer := "203.0.113.10:12345"

	for i := 0; i < 2; i++ {
		if !l.Allow(peer) {
			t.Fatalf("should allow before threshold (%d)", i)
		}
		l.Fail(peer)
	}
	if !l.Allow(peer) {
		t.Fatal("3rd attempt should still be allowed (threshold not reached until after fail)")
	}
	l.Fail(peer) // 3rd failure → lockout
	if l.Allow(peer) {
		t.Fatal("expected lockout")
	}

	l.Success(peer)
	if !l.Allow(peer) {
		t.Fatal("success should clear lockout")
	}
}

func TestLimiterWindowExpiry(t *testing.T) {
	l := NewLimiter(2, 50*time.Millisecond, time.Minute)
	peer := "203.0.113.11:1"
	l.Fail(peer)
	time.Sleep(60 * time.Millisecond)
	l.Fail(peer) // first failure should have aged out; only 1 in window
	if !l.Allow(peer) {
		t.Fatal("should not lock out when failures fall outside window")
	}
}

func TestLimiterBlocked(t *testing.T) {
	l := NewLimiter(1, time.Minute, time.Minute)
	if len(l.Blocked()) != 0 {
		t.Fatal("expected empty")
	}
	l.Fail("198.51.100.7:22")
	blocked := l.Blocked()
	if len(blocked) != 1 || blocked[0].IP != "198.51.100.7" {
		t.Fatalf("blocked=%+v", blocked)
	}
	if blocked[0].Remaining <= 0 {
		t.Fatalf("remaining=%s", blocked[0].Remaining)
	}
}
