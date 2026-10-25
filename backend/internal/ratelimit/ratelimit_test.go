package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	l := New(3, time.Minute)
	l.SetClock(func() time.Time { return now })

	t.Run("sayaç artar", func(t *testing.T) {
		if n, _ := l.Hit("a"); n != 1 {
			t.Fatalf("1 bekleniyordu, gelen %d", n)
		}
		if n, _ := l.Hit("a"); n != 2 {
			t.Fatalf("2 bekleniyordu, gelen %d", n)
		}
	})
	t.Run("Count sayacı artırmaz", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			if n, _ := l.Count("a"); n != 2 {
				t.Fatalf("2 bekleniyordu, gelen %d", n)
			}
		}
	})
	t.Run("anahtarlar bağımsızdır", func(t *testing.T) {
		if n, _ := l.Count("b"); n != 0 {
			t.Fatalf("0 bekleniyordu, gelen %d", n)
		}
	})
	t.Run("kalan süre pencereye göre hesaplanır", func(t *testing.T) {
		now = now.Add(20 * time.Second)
		_, left := l.Count("a")
		if left != 40*time.Second {
			t.Fatalf("40sn bekleniyordu, gelen %v", left)
		}
	})
	t.Run("pencere bitince sıfırlanır", func(t *testing.T) {
		now = now.Add(61 * time.Second)
		if n, _ := l.Count("a"); n != 0 {
			t.Fatalf("0 bekleniyordu, gelen %d", n)
		}
		if n, _ := l.Hit("a"); n != 1 {
			t.Fatalf("1 bekleniyordu, gelen %d", n)
		}
	})
	t.Run("Reset sayacı siler", func(t *testing.T) {
		l.Hit("c")
		l.Reset("c")
		if n, _ := l.Count("c"); n != 0 {
			t.Fatalf("0 bekleniyordu, gelen %d", n)
		}
	})
	t.Run("Max değeri döner", func(t *testing.T) {
		if l.Max() != 3 {
			t.Fatalf("3 bekleniyordu, gelen %d", l.Max())
		}
	})
}