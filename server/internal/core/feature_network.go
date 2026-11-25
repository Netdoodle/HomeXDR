package core

import (
	"context"
	"errors"
	"fmt"
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
	c.AdGuard.SetHistory(c.storeAdGuardHistory)
	if err := c.AdGuard.Load(ctx); err != nil {
		c.Log.Error("load AdGuard Home settings", "err", err)
	}
}

// ingestAdGuard stores lookups read from AdGuard Home as events of the host it runs on,
// which is the firewall's host when AdGuard Home runs there.
func (c *Core) ingestAdGuard(ctx context.Context, evs []*event.Event) error {
	host, err := c.adguardHost(ctx, evs)
	if err != nil {
		return err
	}
	return c.Ingest(ctx, host, evs)
}

// storeAdGuardHistory stores backfilled lookups as they are: no detection rules, so
// history from before the integration was turned on does not raise new alerts.
func (c *Core) storeAdGuardHistory(ctx context.Context, evs []*event.Event) error {
	host, err := c.adguardHost(ctx, evs)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, e := range evs {
		c.normalize(e, host, now)
	}
	return c.Events.Insert(ctx, evs)
}

// adguardHost is the network host the lookups come from (AdGuard Home), named on each event.
func (c *Core) adguardHost(ctx context.Context, evs []*event.Event) (*store.Host, error) {
	u, err := adguard.ParseURL(c.AdGuard.View().URL)
	if err != nil {
		return nil, err
	}
	addr, err := c.adguardAddr(ctx, u.Hostname())
	if err != nil {
		return nil, err
	}
	host, err := c.State.EnsureNetworkHost(ctx, addr, "", "")
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		if e.Observer != nil {
			e.Observer.Hostname = host.Hostname
		}
	}
	return host, nil
}

// adguardIPs remembers the last address each resolver name resolved to.
var adguardIPs sync.Map

// adguardAddr is the IP address of the resolver's host. A name that does not resolve right
// now (often because the resolver itself is restarting) falls back to its last address; one
// that never resolved is an error, so the batch is retried on the next poll instead of
// being filed under a host named after the hostname.
func (c *Core) adguardAddr(ctx context.Context, name string) (string, error) {
	if _, err := netip.ParseAddr(name); err == nil {
		return name, nil
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, name)
	if err == nil && len(ips) > 0 {
		adguardIPs.Store(name, ips[0])
		return ips[0], nil
	}
	if ip, ok := adguardIPs.Load(name); ok {
		return ip.(string), nil
	}
	if err == nil {
		err = errors.New("no addresses")
	}
	return "", fmt.Errorf("look up %s: %w", name, err)
}

// raiseBehavior turns a detector's finding into an alert.
func (c *Core) raiseBehavior(ctx context.Context, f behavior.Finding) error {
	return c.RaiseFinding(ctx, Finding{
		RuleID: f.Rule, Title: f.Title, Description: f.Description, Severity: f.Severity,
		Tags: []string{"network", "behavior"}, Entity: f.Entity, Dataset: "homexdr.behavior", Message: f.Description,
		Hostname: c.homeDevice(f.Source, f.Destination),
		Source:   f.Source, Destination: f.Destination, Data: f.Data,
	})
}

// homeDevice returns the address of the home device a network finding is about, the
// first endpoint that is on the home network, or "" when neither is.
func (c *Core) homeDevice(eps ...*event.Endpoint) string {
	var scope interface{ Home(netip.Addr) bool }
	if c.Inventory != nil {
		if s := c.Inventory.Scope(); s != nil {
			scope = s
		}
	}
	for _, ep := range eps {
		if ep == nil || ep.IP == "" {
			continue
		}
		a, err := netip.ParseAddr(ep.IP)
		if err != nil {
			continue
		}
		if scope != nil && scope.Home(a) || scope == nil && a.IsPrivate() {
			return a.Unmap().String()
		}
	}
	return ""
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
