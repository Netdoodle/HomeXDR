package core

import (
	"context"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// initHealth sets up feed health, the offline lists and vulnerability matching.
func (c *Core) initHealth(ctx context.Context) {}

// runHealth is the background loop of those features.
func (c *Core) runHealth(ctx context.Context) {}

// observeHealth sees every stored batch of events.
func (c *Core) observeHealth(ctx context.Context, host *store.Host, evs []*event.Event) {}
