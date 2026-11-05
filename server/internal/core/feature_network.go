package core

import (
	"context"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const inventoryInterval = 30 * time.Second

// initNetwork sets up device inventory and behaviour detection.
func (c *Core) initNetwork(ctx context.Context) {
	c.Inventory = newInventory(c)
	if err := c.Inventory.load(ctx); err != nil {
		c.Log.Error("load device inventory", "err", err)
	}
}

// runNetwork is the background loop of those features.
func (c *Core) runNetwork(ctx context.Context) {
	tick := time.NewTicker(inventoryInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// One last write; the context is over but the database is still open.
			c.Inventory.flush(context.WithoutCancel(ctx))
			return
		case <-tick.C:
			c.Inventory.flush(ctx)
			c.Inventory.raiseNewDevices(ctx)
		}
	}
}

// observeNetwork sees every stored batch of events.
func (c *Core) observeNetwork(ctx context.Context, host *store.Host, evs []*event.Event) {
	c.Inventory.Observe(host, evs)
}
