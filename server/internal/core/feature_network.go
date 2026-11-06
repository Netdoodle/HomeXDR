package core

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/adguard"
	"github.com/Netdoodle/homexdr/server/internal/behavior"
	"github.com/Netdoodle/homexdr/server/internal/enrich"
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
	c.Behavior = behavior.New(behavior.Deps{
		Events: c.Events, State: c.State, Log: c.Log,
		Enrich: func() enrich.Lookup { return c.Enrich },
		Scope:  c.Inventory.Scope,
		Label:  c.Inventory.DeviceLabel,
		Raise:  c.raiseBehavior,
	})
	if err := c.Behavior.Load(ctx); err != nil {
		c.Log.Error("load behaviour settings", "err", err)
	}
	c.AdGuard = adguard.New(c.State, c.Log, c.ingestAdGuard)
	if err := c.AdGuard.Load(ctx); err != nil {
		c.Log.Error("load AdGuard Home settings", "err", err)
	}
}

// ingestAdGuard stores lookups read from AdGuard Home as events of the host it runs on,
// which is the firewall's host when AdGuard Home runs there.
func (c *Core) ingestAdGuard(ctx context.Context, evs []*event.Event) error {
	u, err := adguard.ParseURL(c.AdGuard.View().URL)
	if err != nil {
		return err
	}
	addr := u.Hostname()
	if _, err := netip.ParseAddr(addr); err != nil {
		if ips, err := net.DefaultResolver.LookupHost(ctx, addr); err == nil && len(ips) > 0 {
			addr = ips[0]
		}
	}
	host, err := c.State.EnsureNetworkHost(ctx, addr, "", "")
	if err != nil {
		return err
	}
	for _, e := range evs {
		if e.Observer != nil {
			e.Observer.Hostname = host.Hostname
		}
	}
	return c.Ingest(ctx, host, evs)
}

// raiseBehavior turns a detector's finding into an alert.
func (c *Core) raiseBehavior(ctx context.Context, f behavior.Finding) error {
	return c.RaiseFinding(ctx, Finding{
		RuleID: f.Rule, Title: f.Title, Description: f.Description, Severity: f.Severity,
		Tags: []string{"network", "behavior"}, Entity: f.Entity, Dataset: "homexdr.behavior", Message: f.Description,
		Source: f.Source, Destination: f.Destination, Data: f.Data,
	})
}

// runNetwork is the background loop of those features.
func (c *Core) runNetwork(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.Behavior.Run(ctx)
	}()
	go func() {
		defer wg.Done()
		c.AdGuard.Run(ctx)
	}()
	tick := time.NewTicker(inventoryInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// One last write; the context is over but the database is still open.
			c.Inventory.flush(context.WithoutCancel(ctx))
			wg.Wait()
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
