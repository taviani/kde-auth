package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterWindow(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	l := New(2, 15*time.Minute)
	l.now = func() time.Time { return now }

	if l.TooMany("ip:1") {
		t.Fatal("empty should allow")
	}
	l.Hit("ip:1")
	l.Hit("ip:1")
	if !l.TooMany("ip:1") {
		t.Fatal("expected block after 2 hits")
	}
	now = now.Add(16 * time.Minute)
	if l.TooMany("ip:1") {
		t.Fatal("window should have elapsed")
	}
	l.Hit("email:a@b.c")
	l.Clear("email:a@b.c")
	if l.TooMany("email:a@b.c") {
		t.Fatal("cleared key should allow")
	}
}
