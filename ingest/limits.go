package main

import (
	"math"
	"sync"
	"time"
)

// limiter is a token bucket per key (a host, or a client address for
// registration), so one misbehaving agent can't crowd out the rest. Each
// ingest replica keeps its own buckets: the limits are generous enough that
// splitting them across replicas doesn't matter, and nothing is shared.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
	sweptAt time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(perMinute, burst int) *limiter {
	return &limiter{
		rate:    float64(perMinute) / 60,
		burst:   float64(burst),
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// allow takes one token for key. When there's none it reports how long
// until there will be.
func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.at).Seconds()*l.rate)
	b.at = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// sweep forgets buckets that have refilled, at most once a minute.
func (l *limiter) sweep(now time.Time) {
	if now.Sub(l.sweptAt) < time.Minute {
		return
	}
	l.sweptAt = now
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.at) > full {
			delete(l.buckets, k)
		}
	}
}
