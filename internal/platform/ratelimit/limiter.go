package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
	now    func() time.Time
}

func New(max int, window time.Duration) *Limiter {
	return &Limiter{
		max:    max,
		window: window,
		hits:   make(map[string][]time.Time),
		now:    time.Now,
	}
}

func (l *Limiter) TooMany(keys ...string) bool {
	if l == nil || l.max <= 0 {
		return false
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		if key == "" {
			continue
		}
		if len(l.pruned(key, now)) >= l.max {
			return true
		}
	}
	return false
}

func (l *Limiter) Hit(keys ...string) {
	if l == nil || l.max <= 0 {
		return
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		if key == "" {
			continue
		}
		xs := append(l.pruned(key, now), now)
		l.hits[key] = xs
	}
}

func (l *Limiter) Clear(keys ...string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		delete(l.hits, key)
	}
}

func (l *Limiter) pruned(key string, now time.Time) []time.Time {
	cutoff := now.Add(-l.window)
	xs := l.hits[key]
	i := 0
	for i < len(xs) && !xs[i].After(cutoff) {
		i++
	}
	xs = xs[i:]
	if len(xs) == 0 {
		delete(l.hits, key)
		return nil
	}
	l.hits[key] = xs
	return xs
}
