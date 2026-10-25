package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	count   int
	resetAt time.Time
}

// Limiter: anahtar başına sabit pencereli sayaç (bellekte, tek örnek).
type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	now    func() time.Time
	m      map[string]*bucket
}

func New(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, now: time.Now, m: map[string]*bucket{}}
}

// SetClock testlerde zamanı denetlemek içindir.
func (l *Limiter) SetClock(f func() time.Time) {
	l.mu.Lock()
	l.now = f
	l.mu.Unlock()
}

func (l *Limiter) Max() int { return l.max }

func (l *Limiter) live(key string, now time.Time) *bucket {
	b := l.m[key]
	if b != nil && !now.Before(b.resetAt) {
		delete(l.m, key)
		return nil
	}
	return b
}

func (l *Limiter) sweep(now time.Time) {
	for k, b := range l.m {
		if !now.Before(b.resetAt) {
			delete(l.m, k)
		}
	}
}

// Hit sayacı bir artırır; yeni değeri ve pencerenin bitmesine kalan süreyi döndürür.
func (l *Limiter) Hit(key string) (int, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.m) > 10000 {
		l.sweep(now)
	}
	b := l.live(key, now)
	if b == nil {
		b = &bucket{resetAt: now.Add(l.window)}
		l.m[key] = b
	}
	b.count++
	return b.count, b.resetAt.Sub(now)
}

// Count sayacı artırmadan okur.
func (l *Limiter) Count(key string) (int, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.live(key, now)
	if b == nil {
		return 0, 0
	}
	return b.count, b.resetAt.Sub(now)
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}