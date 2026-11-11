package adguard

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Backfill imports the resolver's query log from before live importing started, so the
// history it still keeps (its query log retention) becomes searchable too.
//
// It reads backwards from the moment live importing began and stores those lookups
// without running detection rules on them (History, not Ingest), so old lookups don't
// raise new alerts. It runs once: afterwards the state remembers it is done.

// BackfillStatus is the history import's progress.
type BackfillStatus struct {
	State    string     `json:"state"` // "", running, done, error
	Imported int64      `json:"imported"`
	Oldest   *time.Time `json:"oldest,omitempty"` // oldest lookup imported so far
	Error    string     `json:"error,omitempty"`
}

// SetHistory sets where backfilled lookups are stored (without detection).
func (p *Poller) SetHistory(h Ingest) { p.history = h }

// Backfill starts the history import in the background.
func (p *Poller) Backfill(ctx context.Context) error {
	set := p.settings()
	if !set.Enabled || set.Password == "" {
		return &InputError{"turn on reading the resolver's query log first"}
	}
	if p.history == nil {
		return errors.New("history import is not wired")
	}
	var stt state
	if err := p.st.GetKV(ctx, stateKey, &stt); err != nil || stt.Since.IsZero() {
		return &InputError{"wait for the first successful poll, so HomeXDR knows where live importing began"}
	}
	p.mu.Lock()
	if p.backfill.State == "running" {
		p.mu.Unlock()
		return &InputError{"the history import is already running"}
	}
	if stt.Backfilled {
		p.mu.Unlock()
		return &InputError{Product(set.Kind) + "'s history was already imported"}
	}
	p.backfill = BackfillStatus{State: "running"}
	p.mu.Unlock()
	go p.runBackfill(set, stt.Since)
	return nil
}

func (p *Poller) runBackfill(set Settings, since time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Hour)
	defer cancel()
	err := p.backfillOlder(ctx, set, since)
	p.mu.Lock()
	if err != nil {
		p.backfill.State, p.backfill.Error = "error", err.Error()
	} else {
		p.backfill.State = "done"
	}
	n := p.backfill.Imported
	p.mu.Unlock()
	if err != nil {
		p.log.Warn("dns query log: history import failed", "resolver", Product(set.Kind), "imported", n, "err", err)
		return
	}
	var stt state
	if p.st.GetKV(ctx, stateKey, &stt) == nil {
		stt.Backfilled = true
		_ = p.st.SetKV(ctx, stateKey, stt)
	}
	p.log.Info("dns query log: history imported", "resolver", Product(set.Kind), "lookups", n)
}

func (p *Poller) backfillOlder(ctx context.Context, set Settings, since time.Time) error {
	c, err := newSource(set) // its own reader: it runs alongside live polling
	if err != nil {
		return err
	}
	defer c.Close(context.WithoutCancel(ctx))
	olderThan := c.StartBefore(since)
	got := map[string]bool{}
	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		pg, err := c.QueryLog(ctx, olderThan, pageSize)
		if err != nil {
			return fmt.Errorf("page %d: %w", page+1, err)
		}
		evs := make([]*event.Event, 0, len(pg.Data))
		var oldest time.Time
		for i := range pg.Data {
			e := &pg.Data[i]
			// Live importing already has everything from since on; a reader that cannot
			// seek also returns those, and pages can shift and repeat entries.
			if t, ok := e.When(); !ok || !t.Before(since) || got[e.key()] {
				continue
			}
			got[e.key()] = true
			if ev := e.Event(); ev != nil {
				evs = append(evs, ev)
				if oldest.IsZero() || ev.Timestamp.Before(oldest) {
					oldest = ev.Timestamp
				}
			}
		}
		if len(evs) > 0 {
			if err := p.history(ctx, evs); err != nil {
				return err
			}
			p.mu.Lock()
			p.backfill.Imported += int64(len(evs))
			if !oldest.IsZero() {
				o := oldest
				p.backfill.Oldest = &o
			}
			p.mu.Unlock()
		}
		if len(pg.Data) < pageSize || pg.Oldest == "" || pg.Oldest == olderThan {
			return nil
		}
		olderThan = pg.Oldest
	}
}

// BackfillState returns the history import's progress.
func (p *Poller) BackfillState(ctx context.Context) BackfillStatus {
	p.mu.Lock()
	b := p.backfill
	p.mu.Unlock()
	if b.State == "" {
		var stt state
		if p.st.GetKV(ctx, stateKey, &stt) == nil && stt.Backfilled {
			b.State = "done"
		} else if errors.Is(p.st.GetKV(ctx, stateKey, &stt), store.ErrNotFound) {
			b.State = ""
		}
	}
	return b
}
