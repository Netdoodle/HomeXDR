package core

import (
	"context"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// initNetwork sets up device inventory and behaviour detection.
func (c *Core) initNetwork(ctx context.Context) {}

// runNetwork is the background loop of those features.
func (c *Core) runNetwork(ctx context.Context) {}

// observeNetwork sees every stored batch of events.
func (c *Core) observeNetwork(ctx context.Context, host *store.Host, evs []*event.Event) {}
