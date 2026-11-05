package core

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/lists"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/vuln"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Health holds the data health features: feed health, the offline lists and vulnerability
// matching.
type Health struct {
	Feeds *FeedHealth
	Lists *lists.Service
	Vuln  *vuln.Service

	// serving is set when the background loops run, so checks can tell the running server
	// from a command-line tool that knows only what is saved.
	serving          atomic.Bool
	selfCheckRunning atomic.Bool
}

// initHealth sets up feed health, the offline lists and vulnerability matching. It starts
// nothing and writes nothing, because the command line tools build a Core too.
func (c *Core) initHealth(ctx context.Context) {
	c.Health = &Health{
		Feeds: newFeedHealth(c, func() time.Time { return time.Now().UTC() }),
		Lists: lists.New(filepath.Join(c.Cfg.DataDir, "lists"), c.State, c.Log),
	}
	c.Enrich = c.Health.Lists
	c.Intel.SetOffline(c.Health.Lists)
	c.Health.Vuln = vuln.New(c.State, c.Events, c.Health.Lists, vulnNotifier{c}, c.Log)
	if err := c.Health.Feeds.load(ctx); err != nil {
		c.Log.Warn("feed health: load", "err", err)
	}
}

// runHealth is the background loop of those features.
func (c *Core) runHealth(ctx context.Context) {
	c.Health.serving.Store(true)
	var wg sync.WaitGroup
	for _, run := range []func(context.Context){c.Health.Feeds.Run, c.Health.Lists.Run, c.Health.Vuln.Run} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run(ctx)
		}()
	}
	wg.Wait()
}

// observeHealth sees every stored batch of events.
func (c *Core) observeHealth(ctx context.Context, host *store.Host, evs []*event.Event) {
	if c.Health != nil {
		c.Health.Feeds.observe(host, evs)
	}
}
