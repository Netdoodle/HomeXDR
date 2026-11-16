package core

import (
	"fmt"
	"log"
	"strings"
	"testing"
	"time"
)

type refusedClock struct{ t time.Time }

func (c *refusedClock) now() time.Time { return c.t }

func newTestRefused(start time.Time) (*RefusedCounter, *refusedClock) {
	clk := &refusedClock{t: start}
	r := NewRefusedCounter()
	r.now = clk.now
	return r, clk
}

func (r *RefusedCounter) add(ip string, n int) {
	for range n {
		r.Record(ip)
	}
}

var refusedT0 = time.Date(2026, 1, 10, 12, 30, 0, 0, time.UTC)

func TestRefusedBuckets(t *testing.T) {
	r, clk := newTestRefused(refusedT0)
	r.add("203.0.113.1", 4)
	clk.t = clk.t.Add(time.Hour)
	r.add("203.0.113.1", 2)
	rep := r.Report(5)
	if rep.ThisHour != 2 || rep.PreviousHour != 4 || rep.Last24h != 6 {
		t.Fatalf("report = %+v", rep)
	}
	// 23 hours later the first bucket is still inside the window, 24 hours later it is out.
	clk.t = refusedT0.Add(23 * time.Hour)
	if rep := r.Report(5); rep.Last24h != 6 {
		t.Errorf("after 23h: %+v", rep)
	}
	clk.t = refusedT0.Add(24 * time.Hour)
	if rep := r.Report(5); rep.Last24h != 2 {
		t.Errorf("after 24h: %+v", rep)
	}
	clk.t = refusedT0.Add(30 * time.Hour)
	rep = r.Report(5)
	if rep.Last24h != 0 || len(rep.TopSources) != 0 {
		t.Errorf("after 30h: %+v", rep)
	}
}

func TestRefusedTopSources(t *testing.T) {
	r, clk := newTestRefused(refusedT0)
	for i := 1; i <= 7; i++ {
		r.add(fmt.Sprintf("198.51.100.%d", i), i)
	}
	clk.t = clk.t.Add(3 * time.Hour)
	r.add("198.51.100.1", 10) // spread across hours: 11 in total
	r.add("", 3)              // unknown source: counted, not listed
	rep := r.Report(5)
	if rep.Last24h != 28+10+3 {
		t.Errorf("last 24h = %d", rep.Last24h)
	}
	want := []RefusedSource{{"198.51.100.1", 11}, {"198.51.100.7", 7}, {"198.51.100.6", 6}, {"198.51.100.5", 5}, {"198.51.100.4", 4}}
	if len(rep.TopSources) != 5 {
		t.Fatalf("top = %v", rep.TopSources)
	}
	for i, w := range want {
		if rep.TopSources[i] != w {
			t.Errorf("top[%d] = %v, want %v", i, rep.TopSources[i], w)
		}
	}
}

func TestRefusedIPCap(t *testing.T) {
	r, clk := newTestRefused(refusedT0)
	for i := 0; i < refusedMaxIPs; i++ {
		clk.t = refusedT0.Add(time.Duration(i) * time.Millisecond)
		r.Record(fmt.Sprintf("10.0.%d.%d", i/250, i%250))
	}
	if len(r.ips) != refusedMaxIPs {
		t.Fatalf("ips = %d", len(r.ips))
	}
	// Seeing the oldest source again makes it recent, so the next new source evicts the
	// second oldest instead.
	clk.t = refusedT0.Add(time.Second)
	r.Record("10.0.0.0")
	clk.t = clk.t.Add(time.Millisecond)
	r.Record("192.0.2.1")
	if len(r.ips) != refusedMaxIPs {
		t.Fatalf("ips after eviction = %d", len(r.ips))
	}
	if _, ok := r.ips["10.0.0.0"]; !ok {
		t.Error("recently seen source was evicted")
	}
	if _, ok := r.ips["10.0.0.1"]; ok {
		t.Error("least recent source was kept")
	}
	if _, ok := r.ips["192.0.2.1"]; !ok {
		t.Error("new source missing")
	}
	// The hourly totals are unaffected by eviction.
	if rep := r.Report(5); rep.Last24h != refusedMaxIPs+2 {
		t.Errorf("last 24h = %d", rep.Last24h)
	}
}

func TestRefusedLogWriter(t *testing.T) {
	r, _ := newTestRefused(refusedT0)
	var passed strings.Builder
	inner := log.New(&passed, "", 0)
	l := r.ErrorLog(inner)
	l.Printf("http: TLS handshake error from %s: remote error: tls: bad certificate", "203.0.113.9:51234")
	l.Printf("http: TLS handshake error from %s: EOF", "[2001:db8::7]:4000")
	l.Printf("http: some other server error")
	rep := r.Report(5)
	if rep.Last24h != 2 {
		t.Fatalf("counted %d", rep.Last24h)
	}
	if len(rep.TopSources) != 2 || rep.TopSources[0].IP != "2001:db8::7" || rep.TopSources[1].IP != "203.0.113.9" {
		t.Errorf("sources = %v", rep.TopSources)
	}
	if got := strings.Count(passed.String(), "\n"); got != 3 || !strings.Contains(passed.String(), "some other server error") {
		t.Errorf("passed on %d lines: %q", got, passed.String())
	}
}

// fill sets the hourly counts for the hours before the current one: counts[0] is the last
// full hour, counts[1] the hour before it, and so on.
func (r *RefusedCounter) fill(now time.Time, counts ...int) {
	h := hourOf(now)
	for i, n := range counts {
		r.buckets[h-1-int64(i)] = n
	}
}

func TestRefusedSpike(t *testing.T) {
	now := refusedT0 // 12:30
	steady := func(n int) []int {
		s := make([]int, 24)
		for i := range s {
			s[i] = n
		}
		return s
	}

	t.Run("below the minimum", func(t *testing.T) {
		r, _ := newTestRefused(now)
		r.fill(now, 49) // plenty over 3x the zero average, but under 50
		if _, ok := r.Spike(); ok {
			t.Error("fired below 50")
		}
	})
	t.Run("not three times the average", func(t *testing.T) {
		r, _ := newTestRefused(now)
		c := steady(40)
		c[0] = 119 // 3x40 = 120
		r.fill(now, c...)
		if _, ok := r.Spike(); ok {
			t.Error("fired below 3x the average")
		}
	})
	t.Run("fires once, again after six hours", func(t *testing.T) {
		r, clk := newTestRefused(now)
		c := steady(10)
		c[0] = 120
		r.fill(now, c...)
		sp, ok := r.Spike()
		if !ok {
			t.Fatal("did not fire")
		}
		if sp.Count != 120 || sp.Average != 10 {
			t.Errorf("spike = %+v", sp)
		}
		clk.t = now.Add(5 * time.Minute)
		if _, ok := r.Spike(); ok {
			t.Error("fired twice")
		}
		// Five hours later another spike is still inside the quiet period.
		clk.t = now.Add(5 * time.Hour)
		r.fill(clk.t, c...)
		if _, ok := r.Spike(); ok {
			t.Error("fired within 6h")
		}
		clk.t = now.Add(6 * time.Hour)
		r.fill(clk.t, c...)
		if _, ok := r.Spike(); !ok {
			t.Error("did not fire after 6h")
		}
	})
	t.Run("exactly at the thresholds", func(t *testing.T) {
		r, _ := newTestRefused(now)
		c := make([]int, 24)
		c[0] = 50
		for i := 1; i < 24; i++ {
			c[i] = 50 / 3 // average 16.67 -> 3x = 50
		}
		r.fill(now, c...)
		sp, ok := r.Spike()
		if !ok {
			t.Fatalf("did not fire at the thresholds (avg %.2f)", sp.Average)
		}
	})
	t.Run("lists top sources", func(t *testing.T) {
		r, _ := newTestRefused(now)
		r.add("203.0.113.5", 3)
		r.add("203.0.113.6", 1)
		c := make([]int, 24)
		c[0] = 100
		r.fill(now, c...)
		sp, ok := r.Spike()
		if !ok || len(sp.Top) != 2 || sp.Top[0].IP != "203.0.113.5" {
			t.Errorf("spike = %+v ok=%v", sp, ok)
		}
	})
}
