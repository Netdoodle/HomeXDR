package core

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

// Refused connections on the internet-facing agent listener. Every scanner and bot on
// the internet that connects without a valid agent certificate fails the TLS handshake;
// that is normal noise, so each one is only counted. A sharp rise over the usual level
// raises one alert (see RefusedCounter.Spike).
const (
	refusedWindowHours = 24
	// refusedMaxIPs caps the per-source table; the least recently seen source is dropped.
	refusedMaxIPs = 1000
	// RefusedMinCount and RefusedFactor: the last full hour must have at least this many
	// refused connections and at least this multiple of the preceding hours' average.
	RefusedMinCount = 50
	RefusedFactor   = 3
	// RefusedAlertGap is the least time between two alerts.
	RefusedAlertGap = 6 * time.Hour

	refusedMarker = "TLS handshake error"
	// RuleRefusedSpike is the finding's rule ID.
	RuleRefusedSpike = "health:agent-listener-refused"
)

// RefusedSource is one source address and how many connections it had refused.
type RefusedSource struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// RefusedReport is the Data health section about the internet listener.
type RefusedReport struct {
	// Enabled is false when the internet listener is off; the page then shows nothing.
	Enabled bool `json:"enabled"`
	// ThisHour counts since the start of the current clock hour; PreviousHour is the last
	// full hour.
	ThisHour     int             `json:"this_hour"`
	PreviousHour int             `json:"previous_hour"`
	Last24h      int             `json:"last_24h"`
	TopSources   []RefusedSource `json:"top_sources"`
}

// RefusedSpike describes a rise that should raise an alert.
type RefusedSpike struct {
	Count   int
	Average float64
	Top     []RefusedSource
}

type refusedIP struct {
	hours map[int64]int
	last  time.Time
}

// RefusedCounter counts refused connections in hourly buckets for the last 24 hours,
// and per source address for the busiest sources.
type RefusedCounter struct {
	now func() time.Time

	mu        sync.Mutex
	buckets   map[int64]int
	ips       map[string]*refusedIP
	lastAlert time.Time
}

// NewRefusedCounter returns an empty counter.
func NewRefusedCounter() *RefusedCounter {
	return &RefusedCounter{now: time.Now, buckets: map[int64]int{}, ips: map[string]*refusedIP{}}
}

func hourOf(t time.Time) int64 { return t.Unix() / 3600 }

// Record counts one refused connection from ip (which may be empty when unknown).
func (r *RefusedCounter) Record(ip string) {
	now := r.now()
	h := hourOf(now)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buckets[h]++
	r.pruneLocked(h)
	if ip == "" {
		return
	}
	e, ok := r.ips[ip]
	if !ok {
		if len(r.ips) >= refusedMaxIPs {
			r.evictLocked()
		}
		e = &refusedIP{hours: map[int64]int{}}
		r.ips[ip] = e
	}
	e.hours[h]++
	e.last = now
}

// evictLocked drops the least recently seen source.
func (r *RefusedCounter) evictLocked() {
	var oldest string
	var at time.Time
	for ip, e := range r.ips {
		if oldest == "" || e.last.Before(at) {
			oldest, at = ip, e.last
		}
	}
	delete(r.ips, oldest)
}

// pruneLocked drops buckets older than the window (one extra hour is kept: the spike
// check averages the 23 hours before the last full one).
func (r *RefusedCounter) pruneLocked(h int64) {
	for k := range r.buckets {
		if k < h-refusedWindowHours {
			delete(r.buckets, k)
		}
	}
	for ip, e := range r.ips {
		for k := range e.hours {
			if k < h-refusedWindowHours {
				delete(e.hours, k)
			}
		}
		if len(e.hours) == 0 {
			delete(r.ips, ip)
		}
	}
}

// Report returns the counts for the Data health page. Last24h covers the current hour
// and the 23 before it.
func (r *RefusedCounter) Report(n int) RefusedReport {
	h := hourOf(r.now())
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(h)
	rep := RefusedReport{ThisHour: r.buckets[h], PreviousHour: r.buckets[h-1]}
	for i := int64(0); i < refusedWindowHours; i++ {
		rep.Last24h += r.buckets[h-i]
	}
	rep.TopSources = r.topLocked(h, n)
	return rep
}

func (r *RefusedCounter) topLocked(h int64, n int) []RefusedSource {
	out := []RefusedSource{}
	for ip, e := range r.ips {
		total := 0
		for i := int64(0); i < refusedWindowHours; i++ {
			total += e.hours[h-i]
		}
		if total > 0 {
			out = append(out, RefusedSource{IP: ip, Count: total})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	if n >= 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Spike reports whether an alert is due now, and marks it as sent. It is due when the last
// full hour had at least RefusedMinCount refused connections and at least RefusedFactor
// times the average hourly count of the 23 hours before it, and none was sent in the last
// RefusedAlertGap.
func (r *RefusedCounter) Spike() (RefusedSpike, bool) {
	now := r.now()
	h := hourOf(now)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(h)
	count := r.buckets[h-1]
	sum := 0
	for i := int64(2); i <= refusedWindowHours; i++ {
		sum += r.buckets[h-i]
	}
	avg := float64(sum) / (refusedWindowHours - 1)
	if count < RefusedMinCount || float64(count) < RefusedFactor*avg {
		return RefusedSpike{}, false
	}
	if !r.lastAlert.IsZero() && now.Sub(r.lastAlert) < RefusedAlertGap {
		return RefusedSpike{}, false
	}
	r.lastAlert = now
	return RefusedSpike{Count: count, Average: avg, Top: r.topLocked(h, 5)}, true
}

// refusedIPOf extracts the address from "... TLS handshake error from 203.0.113.5:4242: ...".
func refusedIPOf(line string) string {
	_, rest, ok := strings.Cut(line, refusedMarker+" from ")
	if !ok {
		return ""
	}
	tok, _, _ := strings.Cut(rest, " ")
	host, _, err := net.SplitHostPort(strings.TrimSuffix(tok, ":"))
	if err != nil {
		return ""
	}
	return host
}

type refusedWriter struct {
	r     *RefusedCounter
	inner *log.Logger
}

func (w refusedWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\r\n")
	if strings.Contains(line, refusedMarker) {
		w.r.Record(refusedIPOf(line))
	}
	if w.inner != nil {
		w.inner.Print(line)
	}
	return len(p), nil
}

var _ io.Writer = refusedWriter{}

// ErrorLog returns a logger for http.Server.ErrorLog that counts TLS handshake errors and
// passes every line on to inner (which may be nil).
func (r *RefusedCounter) ErrorLog(inner *log.Logger) *log.Logger {
	return log.New(refusedWriter{r, inner}, "", 0)
}

// RefusedReport is the internet listener section of Data health.
func (c *Core) RefusedReport() RefusedReport {
	if c.Cfg.AgentExternalAddr == "" || c.Refused == nil {
		return RefusedReport{TopSources: []RefusedSource{}}
	}
	rep := c.Refused.Report(5)
	rep.Enabled = true
	return rep
}

// CheckRefused raises the finding when the counter says a spike is due.
func (c *Core) CheckRefused(ctx context.Context) {
	if c.Cfg.AgentExternalAddr == "" || c.Refused == nil {
		return
	}
	sp, ok := c.Refused.Spike()
	if !ok {
		return
	}
	var top []string
	for _, s := range sp.Top {
		top = append(top, fmt.Sprintf("%s (%d)", s.IP, s.Count))
	}
	if len(top) == 0 {
		top = []string{"none recorded"}
	}
	f := Finding{
		RuleID:   RuleRefusedSpike,
		Title:    "Many refused connections on the internet agent listener",
		Severity: store.SevMedium,
		Tags:     []string{"homexdr", "agent-listener"},
		Description: fmt.Sprintf("The internet-facing agent listener refused %d connections in the last full hour, "+
			"against an average of %.1f an hour over the 23 hours before. Refused connections are usually scanners; "+
			"a sudden rise can mean someone is probing the listener or guessing at it. Top sources over 24 hours: %s.",
			sp.Count, sp.Average, strings.Join(top, ", ")),
		Entity:  "agent-listener-external",
		Dataset: "homexdr.health",
		Message: fmt.Sprintf("%d refused connections on the internet agent listener in the last hour (average %.1f)", sp.Count, sp.Average),
		Data: map[string]any{
			"refused_last_hour": sp.Count, "refused_hourly_average": sp.Average, "top_sources": sp.Top,
		},
	}
	if err := c.RaiseFinding(ctx, f); err != nil {
		c.Log.Warn("refused connections finding", "err", err)
	}
}

// runRefused checks for a spike every few minutes.
func (c *Core) runRefused(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.CheckRefused(ctx)
		}
	}
}
