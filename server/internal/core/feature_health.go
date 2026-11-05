package core

import (
	"context"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Health holds the data health features: feed health, the offline lists and vulnerability
// matching.
type Health struct {
	Feeds *FeedHealth
}

// initHealth sets up feed health, the offline lists and vulnerability matching. It starts
// nothing and writes nothing, because the command line tools build a Core too.
func (c *Core) initHealth(ctx context.Context) {
	c.Health = &Health{Feeds: newFeedHealth(c, func() time.Time { return time.Now().UTC() })}
	if err := c.Health.Feeds.load(ctx); err != nil {
		c.Log.Warn("feed health: load", "err", err)
	}
}

// runHealth is the background loop of those features.
func (c *Core) runHealth(ctx context.Context) {
	c.Health.Feeds.Run(ctx)
}

// observeHealth sees every stored batch of events.
func (c *Core) observeHealth(ctx context.Context, host *store.Host, evs []*event.Event) {
	if c.Health != nil {
		c.Health.Feeds.observe(host, evs)
	}
}
