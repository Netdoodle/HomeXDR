package backoff

import (
	"testing"
	"time"
)

func TestNextDoublesWithJitterAndCaps(t *testing.T) {
	var b Backoff
	want := []time.Duration{1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300}
	for i, w := range want {
		hi := w * time.Second
		d := b.Next()
		if d < hi/2 || d > hi {
			t.Fatalf("attempt %d: %v not in [%v, %v]", i, d, hi/2, hi)
		}
	}
	if b.Failures() != len(want) {
		t.Fatalf("failures %d", b.Failures())
	}
	b.Reset()
	if d := b.Next(); d > time.Second {
		t.Fatalf("after reset: %v", d)
	}
}

func TestCustomBounds(t *testing.T) {
	b := Backoff{Min: 10 * time.Millisecond, Max: 40 * time.Millisecond}
	for range 10 {
		if d := b.Next(); d > 40*time.Millisecond || d < 5*time.Millisecond {
			t.Fatalf("%v out of bounds", d)
		}
	}
}
