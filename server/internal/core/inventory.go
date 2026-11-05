package core

// The device inventory: what is on the home network. It is filled from every ingested
// batch, so it lives in memory and is written to the database in the background.
//
// Identity follows the DHCP name, then the MAC, then the IP. An address with no MAC yet is
// a provisional "ip:<addr>" record, which merges into the MAC's record once DHCP links
// them. A new randomized MAC that gives a name already known stays that device, so a phone
// that rotates its private address does not look new each time.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/netscope"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	networkSettingsKey = "network_settings"
	networkStartedKey  = "network_started"

	// RuleNewDevice is the new-device finding.
	RuleNewDevice = "net:new-device"

	defaultLearningDays = 3
	maxLearningDays     = 90

	maxDevices       = 4096
	maxDeviceIPs     = 16
	maxDeviceMACs    = 16
	maxHostnames     = 8
	maxFirewallAddrs = 16
	// newDeviceHoldoff gives DHCP time to name a device before the alert goes out.
	newDeviceHoldoff = 10 * time.Minute
	// maxNewDeviceAlerts per pass: a burst spreads over several passes.
	maxNewDeviceAlerts = 10
	agentLinkInterval  = 10 * time.Minute
	destOnlyMaxAge     = 7 * 24 * time.Hour
	provisionalMaxAge  = 90 * 24 * time.Hour
)

// Device sources.
const (
	sourceDHCP     = "dhcp"
	sourceFirewall = "firewall"
	sourceNetFlow  = "netflow"
	sourceDNS      = "dns"
	sourceSuricata = "suricata"
	sourceAgent    = "agent"
)

// NetworkSettings is what the owner sets about the home network.
type NetworkSettings struct {
	// Subnets are the home subnets; empty means every private IPv4 address outside
	// 172.16.0.0/12.
	Subnets []string `json:"subnets"`
	// Exclude is never part of the home network: container bridges, guest networks.
	Exclude []string `json:"exclude"`
	// FirewallIPs adds firewall addresses to the ones learned from its logs.
	FirewallIPs []string `json:"firewall_ips"`
	// NewDeviceAlerts raises an alert for each new device after the learning period.
	NewDeviceAlerts bool `json:"new_device_alerts"`
	// LearningDays is how long after the feature first started no device counts as new.
	LearningDays int `json:"learning_days"`
	// AlertsSince is when NewDeviceAlerts was last turned on: devices first seen while it
	// was off are not new.
	AlertsSince time.Time `json:"alerts_since"`
}

func (s *NetworkSettings) applyDefaults() {
	if s.LearningDays == 0 {
		s.LearningDays = defaultLearningDays
	}
	if s.Subnets == nil {
		s.Subnets = []string{}
	}
	if s.Exclude == nil {
		s.Exclude = []string{}
	}
	if s.FirewallIPs == nil {
		s.FirewallIPs = []string{}
	}
}

func (s *NetworkSettings) validate() error {
	if s.LearningDays < 1 || s.LearningDays > maxLearningDays {
		return &ValidationError{Msg: fmt.Sprintf("the learning period must be 1 to %d days", maxLearningDays)}
	}
	if _, err := netscope.ParseConfig(s.Subnets, s.Exclude, s.FirewallIPs); err != nil {
		return &ValidationError{Msg: err.Error()}
	}
	return nil
}

// Inventory keeps track of the devices on the home network.
type Inventory struct {
	c   *Core
	now func() time.Time

	scope atomic.Pointer[netscope.Scope]

	mu        sync.Mutex
	settings  NetworkSettings
	started   time.Time
	devs      map[string]*store.Device
	byIP      map[string]string
	byMAC     map[string]string
	byName    map[string]string
	subnets   map[string]bool
	dirty     map[string]bool
	deleted   map[string]bool
	wanIfaces map[string]bool
	firewall  []netip.Addr
	agentSeen map[string]time.Time
	lastPrune time.Time
	overflow  uint64
}

func newInventory(c *Core) *Inventory {
	return &Inventory{
		c: c, now: time.Now,
		devs: map[string]*store.Device{}, byIP: map[string]string{}, byMAC: map[string]string{}, byName: map[string]string{},
		subnets: map[string]bool{}, dirty: map[string]bool{}, deleted: map[string]bool{}, wanIfaces: map[string]bool{},
		agentSeen: map[string]time.Time{},
	}
}

// load reads settings and stored devices at startup.
func (inv *Inventory) load(ctx context.Context) error {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	var set NetworkSettings
	switch err := inv.c.State.GetKV(ctx, networkSettingsKey, &set); {
	case errors.Is(err, store.ErrNotFound):
		set = NetworkSettings{NewDeviceAlerts: true}
	case err != nil:
		return err
	}
	set.applyDefaults()
	inv.settings = set
	if err := inv.c.State.GetKV(ctx, networkStartedKey, &inv.started); err != nil {
		inv.started = inv.now().UTC()
		if err := inv.c.State.SetKV(ctx, networkStartedKey, inv.started); err != nil {
			return err
		}
	}
	inv.rebuildScope()
	devs, err := inv.c.State.ListDevices(ctx)
	if err != nil {
		return err
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].LastSeen.Before(devs[j].LastSeen) })
	for _, d := range devs {
		inv.devs[d.ID] = d
		inv.index(d)
	}
	return nil
}

func (inv *Inventory) index(d *store.Device) {
	if d.IP != "" {
		inv.byIP[d.IP] = d.ID
	}
	for _, m := range d.MACs {
		inv.byMAC[m] = d.ID
	}
	if k := nameKey(d.Hostname); k != "" {
		inv.byName[k] = d.ID
	}
	if d.Subnet != "" {
		inv.subnets[d.Subnet] = true
	}
}

// rebuildScope needs inv.mu.
func (inv *Inventory) rebuildScope() {
	cfg, err := netscope.ParseConfig(inv.settings.Subnets, inv.settings.Exclude, inv.settings.FirewallIPs)
	if err != nil {
		inv.c.Log.Warn("network settings", "err", err)
	}
	inv.scope.Store(netscope.New(cfg, inv.firewall))
}

// Scope returns the current view of the home network.
func (inv *Inventory) Scope() *netscope.Scope { return inv.scope.Load() }

// Observe sees every stored batch. It takes no database action.
func (inv *Inventory) Observe(host *store.Host, evs []*event.Event) {
	now := inv.now().UTC()
	if host.Kind != store.HostNetwork {
		inv.linkAgent(host, now)
		return
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for _, e := range evs {
		switch e.Event.Module {
		case event.ModuleOPNsense:
			inv.observeFirewall(host, e, now)
		case event.ModuleDHCP:
			inv.observeDHCP(e, now)
		case event.ModuleNetFlow:
			inv.observeTraffic(e, sourceNetFlow, true, now)
		case event.ModuleDNS:
			inv.observeTraffic(e, sourceDNS, false, now)
		case event.ModuleSuricata:
			inv.observeTraffic(e, sourceSuricata, true, now)
		}
	}
}

func (inv *Inventory) observeFirewall(host *store.Host, e *event.Event, now time.Time) {
	if len(host.IPs) > 0 {
		if a, err := netip.ParseAddr(host.IPs[0]); err == nil {
			inv.learnFirewall(a)
		}
	}
	if e.Source == nil || e.Destination == nil {
		return
	}
	iface, _ := e.Data["interface"].(string)
	src, err1 := netip.ParseAddr(e.Source.IP)
	dst, err2 := netip.ParseAddr(e.Destination.IP)
	if err1 != nil || err2 != nil {
		return
	}
	// A public source leaving towards a public address is the firewall's WAN address after
	// NAT. That marks the interface as WAN, where a private source is spoofed or a modem's
	// own address, not a device of ours.
	if e.Event.Action == "pass" && e.Network != nil && e.Network.Direction == event.DirectionOutbound &&
		netscope.IsPublic(src) && netscope.IsPublic(dst) {
		if iface != "" && !inv.wanIfaces[iface] && len(inv.wanIfaces) < maxFirewallAddrs {
			inv.wanIfaces[iface] = true
		}
		inv.learnFirewall(src)
		return
	}
	if inv.wanIfaces[iface] {
		return
	}
	if d := inv.touch(src, sourceFirewall, false, now); d != nil && iface != "" && d.Interface != iface && e.Network != nil && e.Network.Direction == event.DirectionInbound {
		d.Interface = iface
	}
	if e.Event.Action == "pass" {
		inv.touch(dst, sourceFirewall, true, now)
	}
}

// learnFirewall needs inv.mu.
func (inv *Inventory) learnFirewall(a netip.Addr) {
	a = a.Unmap()
	if slices.Contains(inv.firewall, a) {
		return
	}
	if len(inv.firewall) >= maxFirewallAddrs { // a WAN address changes now and then
		inv.firewall = inv.firewall[1:]
	}
	inv.firewall = append(inv.firewall, a)
	inv.rebuildScope()
	inv.dropOutOfScope()
}

// dropOutOfScope removes records of addresses that no longer count as home, unless the
// owner has named or noted them. It needs inv.mu.
func (inv *Inventory) dropOutOfScope() {
	scope := inv.scope.Load()
	for _, d := range inv.devs {
		if d.Name != "" || d.Note != "" || d.Known || d.IP == "" {
			continue
		}
		if a, err := netip.ParseAddr(d.IP); err == nil && !scope.Home(a) {
			inv.remove(d)
		}
	}
}

func (inv *Inventory) observeTraffic(e *event.Event, source string, withDest bool, now time.Time) {
	if e.Source != nil && e.Source.IP != "" {
		if a, err := netip.ParseAddr(e.Source.IP); err == nil {
			inv.touch(a, source, false, now)
		}
	}
	if withDest && e.Destination != nil && e.Destination.IP != "" {
		if a, err := netip.ParseAddr(e.Destination.IP); err == nil {
			inv.touch(a, source, true, now)
		}
	}
}

// touch records that an address was seen. asDest means it only received traffic, which
// does not prove a device exists: such a record raises no alert until it sends something.
func (inv *Inventory) touch(a netip.Addr, source string, asDest bool, now time.Time) *store.Device {
	a = a.Unmap()
	scope := inv.scope.Load()
	if !scope.Home(a) {
		return nil
	}
	ip := a.String()
	d := inv.devs[inv.byIP[ip]]
	if d == nil {
		if len(inv.devs) >= maxDevices {
			inv.overflow++
			return nil
		}
		d = &store.Device{ID: "ip:" + ip, IP: ip, Subnet: scope.SubnetOf(a), FirstSeen: now, LastSeen: now, DestOnly: asDest, Sources: []string{}, IPs: []store.DeviceIP{}}
		inv.devs[d.ID] = d
		inv.byIP[ip] = d.ID
		inv.subnets[d.Subnet] = true
	}
	if asDest && !d.DestOnly {
		return d // a device that has gone quiet still gets traffic sent to it
	}
	if !asDest {
		d.DestOnly = false
	}
	if now.After(d.LastSeen) {
		d.LastSeen = now
	}
	addIP(d, ip, now)
	if !slices.Contains(d.Sources, source) {
		d.Sources = append(d.Sources, source)
	}
	inv.dirty[d.ID] = true
	return d
}

func addIP(d *store.Device, ip string, now time.Time) {
	for i := range d.IPs {
		if d.IPs[i].IP == ip {
			d.IPs[i].LastSeen = now
			return
		}
	}
	d.IPs = append(d.IPs, store.DeviceIP{IP: ip, FirstSeen: now, LastSeen: now})
	if len(d.IPs) > maxDeviceIPs {
		oldest := 0
		for i := range d.IPs {
			if d.IPs[i].LastSeen.Before(d.IPs[oldest].LastSeen) {
				oldest = i
			}
		}
		d.IPs = slices.Delete(d.IPs, oldest, oldest+1)
	}
}

func (inv *Inventory) observeDHCP(e *event.Event, now time.Time) {
	if e.Source == nil || e.Source.MAC == "" {
		return
	}
	msg, _ := e.Data["dhcp_message"].(string)
	iface, _ := e.Data["interface"].(string)
	switch msg {
	case "ACK":
		inv.bind(e.Source.MAC, e.Source.IP, e.Source.Domain, iface, now)
	case "NAME":
		inv.bind(e.Source.MAC, "", e.Source.Domain, iface, now)
	}
}

// genericNames are hostnames many devices share, so they identify nothing.
var genericNames = map[string]bool{
	"localhost": true, "unknown": true, "none": true, "default": true, "android": true, "iphone": true, "ipad": true,
	"macbook": true, "macbook-air": true, "macbook-pro": true, "galaxy": true, "espressif": true, "esp": true,
	"host": true, "client": true, "device": true, "wlan0": true, "raspberrypi": true, "ubuntu": true, "debian": true,
	"desktop": true, "laptop": true, "pc": true, "tv": true,
}

func nameKey(name string) string {
	k := strings.ToLower(strings.TrimSpace(name))
	if i := strings.IndexByte(k, '.'); i > 0 {
		k = k[:i] // "phone.lan" and "phone" are one name
	}
	if genericNames[k] {
		return ""
	}
	return k
}

func randomizedMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&0x02 != 0
}

// bind applies what DHCP says: this MAC has this address and name.
func (inv *Inventory) bind(mac, ip, hostname, iface string, now time.Time) {
	mac = strings.ToLower(mac)
	scope := inv.scope.Load()
	var addr netip.Addr
	if ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil || !scope.Home(a) {
			return
		}
		addr = a.Unmap()
		ip = addr.String()
	}
	info := inv.c.Enrich.MAC(mac)
	randomized := info.Randomized || randomizedMAC(mac)
	key := nameKey(hostname)

	d := inv.devs[inv.byMAC[mac]]
	if d == nil && key != "" {
		// A new MAC under a name we know is that device when a randomized MAC explains
		// the change. Two real MACs with one name are two devices with a shared name.
		if other := inv.devs[inv.byName[key]]; other != nil && (randomized || other.Randomized) {
			d = other
		}
	}
	if d == nil {
		if len(inv.devs) >= maxDevices {
			inv.overflow++
			return
		}
		d = &store.Device{ID: mac, FirstSeen: now, LastSeen: now, Sources: []string{}, IPs: []store.DeviceIP{}}
		inv.devs[d.ID] = d
	}
	if d.MAC == "" {
		d.MAC = mac
	}
	if !slices.Contains(d.MACs, mac) {
		d.MACs = append(d.MACs, mac)
		if len(d.MACs) > maxDeviceMACs {
			delete(inv.byMAC, d.MACs[0])
			d.MACs = d.MACs[1:]
		}
	}
	inv.byMAC[mac] = d.ID
	d.Randomized = randomized
	if info.Vendor != "" {
		d.Vendor = info.Vendor
	}
	if hostname != "" {
		if d.Hostname != hostname {
			d.Hostname = hostname
			if !slices.Contains(d.Hostnames, hostname) {
				d.Hostnames = append(d.Hostnames, hostname)
				if len(d.Hostnames) > maxHostnames {
					d.Hostnames = d.Hostnames[1:]
				}
			}
		}
		if key != "" {
			inv.byName[key] = d.ID
		}
	}
	if iface != "" {
		d.Interface = iface
	}
	if ip != "" {
		if holderID, ok := inv.byIP[ip]; ok && holderID != d.ID {
			holder := inv.devs[holderID]
			switch {
			case holder == nil:
			case holder.MAC == "":
				inv.merge(holder, d)
			case holder.IP == ip:
				holder.IP = "" // the lease has moved to this device
				inv.dirty[holder.ID] = true
			}
		}
		if d.IP != ip && d.IP != "" && inv.byIP[d.IP] == d.ID {
			delete(inv.byIP, d.IP)
		}
		d.IP = ip
		inv.byIP[ip] = d.ID
		d.Subnet = scope.SubnetOf(addr)
		inv.subnets[d.Subnet] = true
		addIP(d, ip, now)
	}
	if now.After(d.LastSeen) {
		d.LastSeen = now
	}
	d.DestOnly = false
	if !slices.Contains(d.Sources, sourceDHCP) {
		d.Sources = append(d.Sources, sourceDHCP)
	}
	inv.dirty[d.ID] = true
}

// merge folds a provisional record into the device it turned out to be.
func (inv *Inventory) merge(from, into *store.Device) {
	if from.FirstSeen.Before(into.FirstSeen) {
		into.FirstSeen = from.FirstSeen
	}
	if from.LastSeen.After(into.LastSeen) {
		into.LastSeen = from.LastSeen
	}
	for _, ip := range from.IPs {
		if !slices.ContainsFunc(into.IPs, func(x store.DeviceIP) bool { return x.IP == ip.IP }) {
			into.IPs = append(into.IPs, ip)
		}
	}
	if len(into.IPs) > maxDeviceIPs {
		sort.Slice(into.IPs, func(i, j int) bool { return into.IPs[i].LastSeen.After(into.IPs[j].LastSeen) })
		into.IPs = into.IPs[:maxDeviceIPs]
	}
	for _, s := range from.Sources {
		if !slices.Contains(into.Sources, s) {
			into.Sources = append(into.Sources, s)
		}
	}
	if into.Name == "" {
		into.Name = from.Name
	}
	if into.Note == "" {
		into.Note = from.Note
	}
	into.Known = into.Known || from.Known
	if into.HostID == "" {
		into.HostID, into.HostName = from.HostID, from.HostName
	}
	if into.Interface == "" {
		into.Interface = from.Interface
	}
	if into.AlertedAt == nil {
		into.AlertedAt = from.AlertedAt
	}
	inv.remove(from)
	inv.dirty[into.ID] = true
}

// remove needs inv.mu.
func (inv *Inventory) remove(d *store.Device) {
	delete(inv.devs, d.ID)
	delete(inv.dirty, d.ID)
	inv.deleted[d.ID] = true
	if inv.byIP[d.IP] == d.ID {
		delete(inv.byIP, d.IP)
	}
	for _, m := range d.MACs {
		if inv.byMAC[m] == d.ID {
			delete(inv.byMAC, m)
		}
	}
	if k := nameKey(d.Hostname); inv.byName[k] == d.ID {
		delete(inv.byName, k)
	}
}

// linkAgent ties an endpoint agent to the device with its address. It runs at most once
// per interval per host. In automatic mode an agent's address counts only in a subnet seen
// on the wire, so the bridges and tunnels on the host itself stay out.
func (inv *Inventory) linkAgent(host *store.Host, now time.Time) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if now.Sub(inv.agentSeen[host.ID]) < agentLinkInterval {
		return
	}
	if len(inv.agentSeen) >= maxDevices {
		clear(inv.agentSeen)
	}
	inv.agentSeen[host.ID] = now
	auto := len(inv.settings.Subnets) == 0
	scope := inv.scope.Load()
	for _, ip := range host.IPs {
		a, err := netip.ParseAddr(ip)
		if err != nil || !scope.Home(a) {
			continue
		}
		if auto && !inv.subnets[scope.SubnetOf(a)] {
			continue
		}
		d := inv.touch(a, sourceAgent, false, now)
		if d == nil {
			continue
		}
		name := host.Hostname
		if d.HostID != host.ID || d.HostName != name {
			d.HostID, d.HostName = host.ID, name
		}
	}
}

// DeviceView is a device as the console shows it.
type DeviceView struct {
	store.Device
	// New reports a device first seen after learning that nobody has marked as known.
	New bool `json:"new"`
}

// SubnetCount is one subnet with how many devices were seen in it.
type SubnetCount struct {
	Subnet  string `json:"subnet"`
	Devices int    `json:"devices"`
}

// DeviceList is the inventory for the console.
type DeviceList struct {
	Devices       []DeviceView  `json:"devices"`
	Total         int           `json:"total"`
	Learning      bool          `json:"learning"`
	LearningUntil time.Time     `json:"learning_until"`
	Subnets       []SubnetCount `json:"subnets"`
	// Overflow counts addresses ignored because the inventory is full.
	Overflow uint64 `json:"overflow,omitempty"`
}

// learningEnd needs inv.mu.
func (inv *Inventory) learningEnd() time.Time {
	return inv.started.AddDate(0, 0, inv.settings.LearningDays)
}

func (inv *Inventory) isNew(d *store.Device) bool {
	return !d.Known && d.HostID == "" && !d.DestOnly && !d.FirstSeen.Before(inv.learningEnd())
}

// List returns every device, most recently seen first.
func (inv *Inventory) List() DeviceList {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := DeviceList{Devices: make([]DeviceView, 0, len(inv.devs)), Total: len(inv.devs), LearningUntil: inv.learningEnd(), Overflow: inv.overflow}
	out.Learning = inv.now().Before(out.LearningUntil)
	counts := map[string]int{}
	for _, d := range inv.devs {
		out.Devices = append(out.Devices, DeviceView{Device: cloneDevice(d), New: inv.isNew(d)})
		if d.Subnet != "" {
			counts[d.Subnet]++
		}
	}
	sort.Slice(out.Devices, func(i, j int) bool {
		a, b := &out.Devices[i], &out.Devices[j]
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.ID < b.ID
	})
	out.Subnets = make([]SubnetCount, 0, len(counts))
	for s, n := range counts {
		out.Subnets = append(out.Subnets, SubnetCount{Subnet: s, Devices: n})
	}
	sort.Slice(out.Subnets, func(i, j int) bool { return out.Subnets[i].Subnet < out.Subnets[j].Subnet })
	return out
}

func cloneDevice(d *store.Device) store.Device {
	c := *d
	c.MACs = slices.Clone(d.MACs)
	c.IPs = slices.Clone(d.IPs)
	c.Hostnames = slices.Clone(d.Hostnames)
	c.Sources = slices.Clone(d.Sources)
	return c
}

// DevicePatch is what the owner can change on a device. Nil fields stay as they are.
type DevicePatch struct {
	Name  *string `json:"name"`
	Note  *string `json:"note"`
	Known *bool   `json:"known"`
}

// Patch applies the owner's changes to a device.
func (inv *Inventory) Patch(ctx context.Context, id string, p DevicePatch) (*DeviceView, error) {
	if p.Name == nil && p.Note == nil && p.Known == nil {
		return nil, &ValidationError{Msg: "nothing to update"}
	}
	if p.Name != nil && len(*p.Name) > 128 {
		return nil, &ValidationError{Msg: "the name is too long"}
	}
	if p.Note != nil && len(*p.Note) > 2000 {
		return nil, &ValidationError{Msg: "the note is too long"}
	}
	inv.mu.Lock()
	d := inv.devs[id]
	if d == nil {
		inv.mu.Unlock()
		return nil, store.ErrNotFound
	}
	if p.Name != nil {
		d.Name = strings.TrimSpace(*p.Name)
	}
	if p.Note != nil {
		d.Note = strings.TrimSpace(*p.Note)
	}
	if p.Known != nil {
		d.Known = *p.Known
	}
	view := &DeviceView{Device: cloneDevice(d), New: inv.isNew(d)}
	save := cloneDevice(d)
	delete(inv.dirty, id)
	inv.mu.Unlock()
	if err := inv.c.State.SaveDevices(ctx, []*store.Device{&save}, nil); err != nil {
		inv.mu.Lock()
		inv.dirty[id] = true
		inv.mu.Unlock()
		return nil, err
	}
	return view, nil
}

// Settings returns the current settings.
func (inv *Inventory) Settings() NetworkSettings {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return inv.settings
}

// FirewallAddrs lists the firewall addresses learned from its logs.
func (inv *Inventory) FirewallAddrs() []string {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := make([]string, 0, len(inv.firewall))
	for _, a := range inv.firewall {
		out = append(out, a.String())
	}
	return out
}

// SetSettings validates and stores new settings. Records of addresses that no longer
// count as home are dropped, unless the owner has named or noted them.
func (inv *Inventory) SetSettings(ctx context.Context, set NetworkSettings) (NetworkSettings, error) {
	set.applyDefaults()
	if err := set.validate(); err != nil {
		return set, err
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if set.NewDeviceAlerts && !inv.settings.NewDeviceAlerts {
		set.AlertsSince = inv.now().UTC()
	} else {
		set.AlertsSince = inv.settings.AlertsSince
	}
	if err := inv.c.State.SetKV(ctx, networkSettingsKey, set); err != nil {
		return set, err
	}
	inv.settings = set
	inv.rebuildScope()
	inv.dropOutOfScope()
	return set, nil
}

// flush writes changed devices, and prunes old records now and then.
func (inv *Inventory) flush(ctx context.Context) {
	inv.mu.Lock()
	now := inv.now().UTC()
	if now.Sub(inv.lastPrune) > time.Hour {
		inv.lastPrune = now
		for _, d := range inv.devs {
			if d.Name != "" || d.Note != "" || d.Known || d.HostID != "" {
				continue
			}
			age := now.Sub(d.LastSeen)
			if (d.DestOnly && age > destOnlyMaxAge) || (d.MAC == "" && age > provisionalMaxAge) {
				inv.remove(d)
			}
		}
	}
	changed := make([]*store.Device, 0, len(inv.dirty))
	for id := range inv.dirty {
		if d := inv.devs[id]; d != nil {
			c := cloneDevice(d)
			changed = append(changed, &c)
		}
	}
	deleted := make([]string, 0, len(inv.deleted))
	for id := range inv.deleted {
		if inv.devs[id] == nil {
			deleted = append(deleted, id)
		}
	}
	inv.dirty, inv.deleted = map[string]bool{}, map[string]bool{}
	inv.mu.Unlock()
	if err := inv.c.State.SaveDevices(ctx, changed, deleted); err != nil {
		inv.c.Log.Warn("save devices", "err", err)
		inv.mu.Lock()
		for _, d := range changed {
			inv.dirty[d.ID] = true
		}
		for _, id := range deleted {
			inv.deleted[id] = true
		}
		inv.mu.Unlock()
	}
}

// raiseNewDevices alerts on devices that appeared after the learning period.
func (inv *Inventory) raiseNewDevices(ctx context.Context) {
	inv.mu.Lock()
	if !inv.settings.NewDeviceAlerts {
		inv.mu.Unlock()
		return
	}
	now := inv.now().UTC()
	since := inv.learningEnd()
	if inv.settings.AlertsSince.After(since) {
		since = inv.settings.AlertsSince
	}
	var due []store.Device
	for _, d := range inv.devs {
		if d.AlertedAt != nil || !inv.isNew(d) || d.FirstSeen.Before(since) || now.Sub(d.FirstSeen) < newDeviceHoldoff {
			continue
		}
		due = append(due, cloneDevice(d))
	}
	sort.Slice(due, func(i, j int) bool { return due[i].FirstSeen.Before(due[j].FirstSeen) })
	if len(due) > maxNewDeviceAlerts {
		due = due[:maxNewDeviceAlerts]
	}
	inv.mu.Unlock()
	for i := range due {
		d := &due[i]
		if err := inv.c.RaiseFinding(ctx, newDeviceFinding(d)); err != nil {
			inv.c.Log.Warn("new device alert", "device", d.ID, "err", err)
			return
		}
		inv.mu.Lock()
		if cur := inv.devs[d.ID]; cur != nil {
			t := now
			cur.AlertedAt = &t
			inv.dirty[d.ID] = true
		}
		inv.mu.Unlock()
	}
}

func newDeviceFinding(d *store.Device) Finding {
	data := map[string]any{"device_id": d.ID, "sources": d.Sources, "subnet": d.Subnet, "first_seen": d.FirstSeen.Format(time.RFC3339)}
	var title, desc string
	if d.MAC != "" {
		data["mac"], data["randomized_mac"], data["vendor"], data["hostname"] = d.MAC, d.Randomized, d.Vendor, d.Hostname
		who := d.MAC
		if d.Vendor != "" {
			who += ", " + d.Vendor
		}
		if d.Hostname != "" {
			who = fmt.Sprintf("the name %q (%s)", d.Hostname, who)
		}
		title = "New device on the network"
		desc = fmt.Sprintf("A device HomeXDR has not seen before joined the network: %s, at %s on %s. If you recognize it, mark it as known on the Devices page. If you do not, find out what it is.", who, orNone(d.IP), orNone(d.Subnet))
		if d.Randomized {
			desc += " Its MAC address is randomized, so this may be a phone or laptop you know that changed its private address."
		}
	} else {
		title = "New address on the network"
		desc = fmt.Sprintf("An address not seen before is in use: %s, on %s, seen in %s. This is not proof of a new device: there is no MAC address for it, and a device you know may simply have a new address. DHCP logs tell the two apart (see docs/network-visibility.md).", d.IP, orNone(d.Subnet), strings.Join(d.Sources, ", "))
	}
	return Finding{
		RuleID: RuleNewDevice, Title: title, Description: desc, Severity: store.SevLow,
		Tags: []string{"network", "inventory"}, Entity: d.ID, Dataset: "homexdr.network", Message: desc,
		Source: &event.Endpoint{IP: d.IP, MAC: d.MAC, Domain: d.Hostname}, Data: data,
	}
}

func orNone(s string) string {
	if s == "" {
		return "an unknown address"
	}
	return s
}

// DeviceLabel names the device using an address, for findings about it. key is stable
// across address changes, when the device's MAC is known.
func (inv *Inventory) DeviceLabel(ip string) (key, label string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	d := inv.devs[inv.byIP[ip]]
	if d == nil {
		return "ip:" + ip, ip
	}
	label = d.Name
	if label == "" {
		label = d.Hostname
	}
	if label == "" {
		label = d.HostName
	}
	if label == "" || label == ip {
		return d.ID, ip
	}
	return d.ID, fmt.Sprintf("%s (%s)", label, ip)
}
