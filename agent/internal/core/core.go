// Package core is the agent runtime: it loads the local config, identity and state,
// runs the sensors through the pipeline into the spool, and runs the three protocol
// loops (heartbeat, events, commands) against the server.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/backoff"
	"github.com/Netdoodle/homexdr/agent/internal/collect"
	"github.com/Netdoodle/homexdr/agent/internal/commands"
	"github.com/Netdoodle/homexdr/agent/internal/config"
	"github.com/Netdoodle/homexdr/agent/internal/fileops"
	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/agent/internal/identity"
	"github.com/Netdoodle/homexdr/agent/internal/pipeline"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/agent/internal/selfupdate"
	"github.com/Netdoodle/homexdr/agent/internal/sensors/fim"
	"github.com/Netdoodle/homexdr/agent/internal/sensors/inventory"
	"github.com/Netdoodle/homexdr/agent/internal/sensors/logtail"
	"github.com/Netdoodle/homexdr/agent/internal/spool"
	"github.com/Netdoodle/homexdr/agent/internal/state"
	"github.com/Netdoodle/homexdr/agent/internal/supervisor"
	"github.com/Netdoodle/homexdr/agent/internal/transport"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
	"github.com/Netdoodle/homexdr/shared/version"
)

// netResolver resolves the server name for isolation (replaceable in tests).
var netResolver = net.DefaultResolver

// Data dir layout (besides the identity files, see package identity).
const (
	SpoolDir      = "spool"
	QuarantineDir = "quarantine"
	StatusFile    = "status.json"
)

// ErrRestart is returned by Run after a new agent binary was installed; the caller
// should restart into it (selfupdate.Exec).
var ErrRestart = errors.New("agent updated; restart required")

// DataDir returns the data dir configured in c, or the platform default.
func DataDir(c config.Local, p platform.Platform) string {
	if c.DataDir != "" {
		return c.DataDir
	}
	return p.Paths().DataDir
}

// EnsurePrivateDir creates dir with 0700 and lets the platform restrict it further.
func EnsurePrivateDir(p platform.Platform, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o700)
	if pp, ok := p.(platform.PathProtector); ok {
		if err := pp.ProtectPath(dir); err != nil {
			return fmt.Errorf("protect %s: %w", dir, err)
		}
	}
	return nil
}

// Agent is a loaded, enrolled agent.
type Agent struct {
	plat       platform.Platform
	configPath string
	local      config.Local
	dataDir    string
	log        *slog.Logger
	id         *identity.Identity
	st         *state.Store
	startedAt  time.Time

	spool      *spool.Spool
	pipe       *pipeline.Pipeline
	sup        *supervisor.Supervisor
	client     *transport.Client
	responder  platform.Responder
	collectors map[string]platform.Collector
	handler    *commands.Handler
	env        platform.Env

	sent    atomic.Uint64
	dropped atomic.Uint64

	hostMu   sync.Mutex
	host     api.HostInfo
	hostAt   time.Time
	cfgMu    sync.Mutex // serializes config application
	isoMu    sync.Mutex // serializes isolate/release
	pollNow  chan struct{}
	hbMu     sync.Mutex
	lastHB   time.Time
	lastHBEr string

	// Self-update (nil updater when the local config does not allow it).
	updater   *selfupdate.Updater
	updating  atomic.Bool
	updateErr atomic.Pointer[string] // last failed update attempt, reported in heartbeats
	offered   string                 // last offered version that was logged
	lastRenew time.Time              // last certificate renewal attempt
	confirmed bool                   // a pending update was checked after the first heartbeat
	stop      context.CancelCauseFunc
}

// Load reads the config file, identity and state.
func Load(p platform.Platform, configPath string, log *slog.Logger) (*Agent, error) {
	local, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	if local.ServerURL == "" {
		return nil, fmt.Errorf("%s: server_url is empty; enroll first", configPath)
	}
	dataDir := DataDir(local, p)
	if !identity.Exists(dataDir) {
		return nil, fmt.Errorf("no enrolled identity in %s; run `homexdr-agent enroll` first", dataDir)
	}
	id, err := identity.Load(dataDir)
	if err != nil {
		return nil, err
	}
	if err := EnsurePrivateDir(p, dataDir); err != nil {
		return nil, err
	}
	st, err := state.Open(filepath.Join(dataDir, state.FileName))
	if err != nil {
		return nil, err
	}
	return &Agent{
		plat: p, configPath: configPath, local: local, dataDir: dataDir, log: log,
		id: id, st: st, pollNow: make(chan struct{}, 1),
	}, nil
}

// ID returns the agent ID.
func (a *Agent) ID() string { return a.id.AgentID }

// Run runs the agent until ctx is cancelled. Queued events stay in the spool on disk.
// It returns ErrRestart when it stopped to run a newly installed version.
func (a *Agent) Run(ctx context.Context) error {
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	a.stop = stop
	a.startedAt = time.Now().UTC()
	cfg := a.st.Config()
	sp, err := spool.Open(filepath.Join(a.dataDir, SpoolDir), cfg.SpoolMaxBytes, a.log)
	if err != nil {
		return fmt.Errorf("open spool: %w", err)
	}
	a.spool = sp
	sp.SetThreshold(cfg.Batch.MaxEvents)
	defer func() {
		if err := sp.Close(); err != nil {
			a.log.Warn("close spool", "err", err)
		}
	}()

	host := a.hostInfo(ctx)
	a.pipe = pipeline.New(a.id.AgentID, version.Version, host.Hostname, sp, a.log)
	a.pipe.SetFilters(cfg.Filters)
	a.env = platform.Env{AgentID: a.id.AgentID, DataDir: a.dataDir, Log: a.log}
	a.responder = a.plat.Responder(a.env)
	a.collectors = MergeCollectors(a.plat, a.env)
	client, err := transport.New(a.local.ServerURL, a.id)
	if err != nil {
		return err
	}
	a.client = client
	defer client.Close()

	exe, _ := os.Executable()
	a.updater = a.newUpdater(client)
	a.handler = &commands.Handler{
		API: client,
		Verifier: &commands.Verifier{
			AgentID: a.id.AgentID, Key: a.id.CommandKey, Seen: a.st, Policy: a.local.Allowed,
		},
		Responder:  a.responder,
		Isolator:   a,
		Collectors: a.collectors,
		Files:      fileops.NewStore(filepath.Join(a.dataDir, QuarantineDir), a.dataDir, a.configPath, exe),
		Log:        a.log,
		Platform:   a.plat.Name(),
	}

	a.log.Info("homexdr agent starting",
		"version", version.String(), "agent_id", a.id.AgentID, "server", a.local.ServerURL,
		"platform", a.plat.Name(), "data_dir", a.dataDir, "allowed_actions", a.local.AllowedActions)

	if a.st.Snapshot().Isolated {
		a.reapplyIsolation(ctx)
	} else if a.responder.Isolated() {
		// Rules without saved state (e.g. a crash between applying and persisting):
		// remove them rather than leave the host cut off with nobody tracking it.
		a.log.Warn("found isolation rules but the saved state says not isolated; releasing")
		if err := a.responder.Release(ctx); err != nil {
			a.log.Error("cannot release stale isolation", "err", err)
		}
	}

	sensorCtx, stopSensors := context.WithCancel(ctx)
	defer stopSensors()
	a.sup = supervisor.New(a.pipe, a.log)
	a.applySensors(sensorCtx, cfg)

	var wg sync.WaitGroup
	for _, loop := range []func(context.Context){a.heartbeatLoop, a.senderLoop, a.commandLoop, a.flushLoop} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			loop(ctx)
		}()
	}
	<-ctx.Done()
	a.log.Info("homexdr agent stopping")
	a.sup.Stop()
	wg.Wait()
	a.writeStatus()
	if errors.Is(context.Cause(ctx), ErrRestart) {
		return ErrRestart
	}
	return nil
}

// --- self-update ---

// Executable returns the resolved path of the running binary.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return exe, nil
}

func (a *Agent) newUpdater(client *transport.Client) *selfupdate.Updater {
	if !a.local.AutoUpdate {
		return nil
	}
	if !selfupdate.Supported() {
		a.log.Warn("auto_update is set but this platform cannot update itself yet")
		return nil
	}
	key, err := api.ParseUpdateKey(a.local.UpdateKey)
	if err != nil {
		a.log.Error("auto_update is set but update_key is invalid", "err", err)
		return nil
	}
	exe, err := Executable()
	if err != nil {
		a.log.Error("auto_update: cannot find the agent binary", "err", err)
		return nil
	}
	return &selfupdate.Updater{
		Key: key, Exe: exe, DataDir: a.dataDir, Fetcher: client, Log: a.log,
		Version: version.Version, CommitTime: version.CommitUnix(),
	}
}

// afterHeartbeat confirms a pending update once and acts on an update offer.
func (a *Agent) afterHeartbeat(ctx context.Context, offer *api.AgentUpdate) {
	if !a.confirmed {
		a.confirmed = true
		if m, ok := selfupdate.Confirm(a.dataDir, version.Version); ok {
			a.log.Info("agent update confirmed", "version", m.Version, "previous_version", m.PreviousVersion)
		}
	}
	if offer == nil {
		return
	}
	if a.updater == nil {
		if a.offered != offer.Version {
			a.offered = offer.Version
			a.log.Info("server offers a different agent version; automatic updates are off in the local config",
				"offered", offer.Version, "running", version.Version)
		}
		return
	}
	if !a.updating.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer a.updating.Store(false)
		rel, err := a.updater.Install(ctx, *offer)
		switch {
		case err != nil:
			if a.offered != offer.Version || !errors.Is(err, selfupdate.ErrNotNewer) {
				a.log.Warn("agent update not installed", "offered", offer.Version, "err", err)
			}
			if !errors.Is(err, selfupdate.ErrNotNewer) {
				msg := fmt.Sprintf("%s: %v", offer.Version, err)
				a.updateErr.Store(&msg)
			}
			a.offered = offer.Version
		case rel != nil:
			a.updateErr.Store(nil)
			a.log.Info("installed agent update; restarting", "version", rel.Version, "previous_version", version.Version)
			a.stop(ErrRestart)
		}
	}()
}

// --- config and sensors ---

func fingerprint(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// sensorKinds are the sensor kinds reported per platform even when not running.
func sensorKinds(plat string) []string {
	if plat == event.PlatformWindows {
		return []string{"process", "network", "file", "registry", "dns", "library", "auth", "eventlog"}
	}
	return []string{"process", "network", "file", "dns", "library", "auth"}
}

func kindConfig(kind string, s api.SensorsConfig) (any, bool) {
	switch kind {
	case "process":
		return s.Process, s.Process.Enabled
	case "network":
		return s.Network, s.Network.Enabled
	case "file":
		return s.File, s.File.Enabled
	case "registry":
		return s.Registry, s.Registry.Enabled
	case "dns":
		return s.DNS, s.DNS.Enabled
	case "library":
		return s.Library, s.Library.Enabled
	case "auth":
		return s.Auth, s.Auth.Enabled
	case "eventlog":
		return s.EventLog, s.EventLog.Enabled
	}
	return s, true
}

func (a *Agent) applySensors(ctx context.Context, cfg api.AgentConfig) {
	var specs []supervisor.Spec
	running := map[string]bool{}
	for _, s := range a.plat.Sensors(cfg.Sensors, a.env) {
		if s == nil {
			continue
		}
		sub, _ := kindConfig(s.Name(), cfg.Sensors)
		specs = append(specs, supervisor.Spec{Sensor: s, Key: fingerprint(sub)})
		running[s.Name()] = true
	}
	var disabled []api.SensorStatus
	for _, kind := range sensorKinds(a.plat.Name()) {
		if running[kind] {
			continue
		}
		st := api.SensorStatus{Name: kind, State: api.SensorDisabled}
		if _, on := kindConfig(kind, cfg.Sensors); on {
			st.Error = "not available on this platform"
		}
		disabled = append(disabled, st)
	}
	paths := a.plat.Paths()
	if cfg.FIM.Enabled {
		specs = append(specs, supervisor.Spec{Sensor: fim.New(cfg.FIM, paths.FIMDefaults, a.dataDir, a.log), Key: fingerprint(cfg.FIM)})
	} else {
		disabled = append(disabled, api.SensorStatus{Name: "fim", Impl: event.ModuleFIM, State: api.SensorDisabled})
	}
	if len(cfg.Logs) > 0 {
		specs = append(specs, supervisor.Spec{Sensor: logtail.New(cfg.Logs, a.dataDir, a.log), Key: fingerprint(cfg.Logs)})
	}
	inv := map[string]platform.Collector{}
	for _, name := range inventory.Artifacts {
		if c, ok := a.collectors[name]; ok {
			inv[name] = c
		}
	}
	if len(inv) > 0 {
		specs = append(specs, supervisor.Spec{
			Sensor: inventory.New(inv, cfg.InventoryIntervalSec, a.st, a.log),
			Key:    fingerprint(cfg.InventoryIntervalSec),
		})
	}
	a.sup.Apply(ctx, specs, disabled)
}

// applyConfig stores and applies a new central config. Local policy is not affected.
func (a *Agent) applyConfig(ctx context.Context, c api.AgentConfig) {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	c = state.Sanitize(c)
	if err := a.st.SetConfig(c); err != nil {
		a.log.Warn("cannot persist central config", "err", err)
	}
	a.pipe.SetFilters(c.Filters)
	a.spool.SetMaxBytes(c.SpoolMaxBytes)
	a.spool.SetThreshold(c.Batch.MaxEvents)
	a.applySensors(ctx, c)
	a.log.Info("applied central config", "version", c.Version, "filters", len(c.Filters))
}

// --- isolation (commands.Isolator) ---

func (a *Agent) serverAddrs(ctx context.Context, fallback []string) ([]netip.Addr, int, error) {
	u, err := transport.ParseServerURL(a.local.ServerURL)
	if err != nil {
		return nil, 0, err
	}
	host, port := transport.ServerHostPort(u)
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		res, rerr := netResolver.LookupNetIP(rctx, "ip", host)
		cancel()
		for _, r := range res {
			ips = append(ips, r.Unmap())
		}
		if rerr != nil {
			a.log.Warn("cannot resolve server name for isolation", "host", host, "err", rerr)
		}
	}
	for _, s := range fallback {
		if ip, err := netip.ParseAddr(s); err == nil && !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, 0, errors.New("cannot resolve the server address; refusing to isolate because the agent would lose its connection")
	}
	return ips, port, nil
}

func addrStrings(ips []netip.Addr) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

// Isolate builds the isolation spec (server address, command allow list and local
// isolation_allow), applies it and persists the state.
func (a *Agent) Isolate(ctx context.Context, p api.IsolateParams) (any, error) {
	a.isoMu.Lock()
	defer a.isoMu.Unlock()
	allow := slices.Concat(p.Allow, a.local.IsolationAllow)
	prefixes, err := config.ParsePrefixes(allow)
	if err != nil {
		return nil, fmt.Errorf("allow: %w", err)
	}
	ips, port, err := a.serverAddrs(ctx, a.st.Snapshot().ServerIPs)
	if err != nil {
		return nil, err
	}
	iso := platform.Isolation{ServerIPs: ips, ServerPort: port, Allow: prefixes}
	if err := a.responder.Isolate(ctx, iso); err != nil {
		return nil, err
	}
	if err := a.st.SetIsolated(true, allow, addrStrings(ips)); err != nil {
		a.log.Warn("cannot persist isolation state", "err", err)
	}
	a.log.Warn("host isolated", "server_ips", addrStrings(ips), "server_port", port, "allow", allow)
	return map[string]any{"server_ips": addrStrings(ips), "server_port": port, "allow": allow}, nil
}

// Release removes isolation and persists the state.
func (a *Agent) Release(ctx context.Context) error {
	a.isoMu.Lock()
	defer a.isoMu.Unlock()
	if err := a.responder.Release(ctx); err != nil {
		return err
	}
	if err := a.st.SetIsolated(false, nil, nil); err != nil {
		a.log.Warn("cannot persist isolation state", "err", err)
	}
	a.log.Warn("host isolation released")
	return nil
}

func (a *Agent) reapplyIsolation(ctx context.Context) {
	snap := a.st.Snapshot()
	prefixes, err := config.ParsePrefixes(slices.Concat(snap.IsolationAllow, a.local.IsolationAllow))
	if err != nil {
		a.log.Error("isolation state has an invalid allow list", "err", err)
	}
	ips, port, err := a.serverAddrs(ctx, snap.ServerIPs)
	if err != nil {
		a.log.Error("cannot re-apply host isolation", "err", err)
		return
	}
	if err := a.responder.Isolate(ctx, platform.Isolation{ServerIPs: ips, ServerPort: port, Allow: prefixes}); err != nil {
		a.log.Error("cannot re-apply host isolation", "err", err)
		return
	}
	a.log.Warn("host isolation re-applied from saved state", "server_ips", addrStrings(ips))
}

// --- loops ---

func (a *Agent) hostInfo(ctx context.Context) api.HostInfo {
	a.hostMu.Lock()
	defer a.hostMu.Unlock()
	if a.hostAt.IsZero() || time.Since(a.hostAt) > 10*time.Minute {
		a.host = a.plat.HostInfo(ctx)
		if a.host.OS.Platform == "" {
			a.host.OS.Platform = a.plat.Name()
		}
		a.hostAt = time.Now()
		if a.pipe != nil {
			a.pipe.SetHostname(a.host.Hostname)
		}
	}
	return a.host
}

func (a *Agent) status() api.AgentStatus {
	cfg := a.st.Config()
	stats := a.spool.Stats()
	_, _, failed := a.pipe.Counters()
	isolated := a.st.Snapshot().Isolated
	return api.AgentStatus{
		Version:        version.Version,
		StartedAt:      a.startedAt,
		ConfigVersion:  cfg.Version,
		QueueEvents:    stats.Events,
		QueueBytes:     stats.Bytes,
		EventsSent:     a.sent.Load(),
		EventsDropped:  a.dropped.Load() + stats.Dropped + failed,
		Isolated:       isolated,
		Sensors:        a.sup.Statuses(),
		AllowedActions: slices.Clone(a.local.AllowedActions),
		AutoUpdate:     a.updater != nil,
		UpdateError:    a.lastUpdateError(),
	}
}

func (a *Agent) lastUpdateError() string {
	if p := a.updateErr.Load(); p != nil {
		return *p
	}
	return ""
}

// renewWhenLeft is the share of the certificate lifetime left at which the agent renews
// (about four months for a one-year certificate).
const renewWhenLeft = 3

// maybeRenew renews the client certificate when a third of its lifetime is left or it
// has expired, retrying hourly (every five minutes once expired).
func (a *Agent) maybeRenew(ctx context.Context) {
	cert := a.id.Certificate()
	left := time.Until(cert.NotAfter)
	if left > cert.NotAfter.Sub(cert.NotBefore)/renewWhenLeft {
		return
	}
	retry := time.Hour
	if left <= 0 {
		retry = 5 * time.Minute
	}
	if time.Since(a.lastRenew) < retry {
		return
	}
	a.lastRenew = time.Now()
	key, err := identity.NewKey()
	if err != nil {
		a.log.Error("certificate renewal: new key", "err", err)
		return
	}
	csr, err := identity.CSR(key, a.id.AgentID) // the server ignores the subject
	if err != nil {
		a.log.Error("certificate renewal: CSR", "err", err)
		return
	}
	certPEM, err := a.client.Renew(ctx, csr)
	if err != nil {
		level := slog.LevelWarn
		if left <= 0 || transport.IsStatus(err, 403) {
			level = slog.LevelError
		}
		a.log.Log(ctx, level, "certificate renewal failed", "expires", cert.NotAfter, "err", err)
		return
	}
	if err := a.id.Renew(a.dataDir, key, certPEM); err != nil {
		a.log.Error("certificate renewal: save", "err", err)
		return
	}
	a.client.Close() // new connections present the renewed certificate
	a.log.Info("renewed client certificate", "previous_expiry", cert.NotAfter, "expires", a.id.Certificate().NotAfter)
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	var bo backoff.Backoff
	for ctx.Err() == nil {
		a.maybeRenew(ctx)
		hb := api.Heartbeat{Host: a.hostInfo(ctx), Status: a.status()}
		resp, err := a.client.Heartbeat(ctx, hb)
		a.hbMu.Lock()
		if err != nil {
			a.lastHBEr = err.Error()
		} else {
			a.lastHB, a.lastHBEr = time.Now().UTC(), ""
		}
		a.hbMu.Unlock()
		a.writeStatus()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			level := slog.LevelWarn
			if bo.Failures() > 0 {
				level = slog.LevelDebug
			}
			if transport.IsStatus(err, 401) || transport.IsStatus(err, 403) {
				level = slog.LevelError // revoked or superseded certificate
			}
			a.log.Log(ctx, level, "heartbeat failed", "err", err)
			bo.Sleep(ctx)
			continue
		}
		bo.Reset()
		if resp.Config != nil && resp.Config.Version != a.st.Config().Version {
			a.applyConfig(ctx, *resp.Config)
		}
		a.afterHeartbeat(ctx, resp.Update)
		if resp.CommandsPending {
			select {
			case a.pollNow <- struct{}{}:
			default:
			}
		}
		backoff.SleepCtx(ctx, time.Duration(a.st.Config().HeartbeatIntervalSec)*time.Second)
	}
}

// maxBatchBytes leaves headroom under the server's limit.
const maxBatchBytes = api.MaxEventBatchBytes - 64<<10

func (a *Agent) senderLoop(ctx context.Context) {
	var bo backoff.Backoff
	for {
		flush := time.Duration(a.st.Config().Batch.FlushIntervalMs) * time.Millisecond
		t := time.NewTimer(flush)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-a.spool.Ready():
		case <-t.C:
		}
		t.Stop()
		for ctx.Err() == nil {
			b, err := a.spool.Next(a.st.Config().Batch.MaxEvents, maxBatchBytes)
			if err != nil {
				a.log.Warn("read spool", "err", err)
				break
			}
			if b == nil {
				break
			}
			if err := a.sendRange(ctx, b, 0, len(b.Lines)); err != nil {
				if ctx.Err() != nil {
					return
				}
				d := bo.Next()
				a.log.Warn("sending events failed; will retry", "err", err, "retry_in", d.Round(time.Second))
				backoff.SleepCtx(ctx, d)
				break
			}
			bo.Reset()
		}
	}
}

// sendRange posts lines[lo:hi], splitting on 413 and dropping batches the server
// rejects as invalid. Delivered lines are committed as they go, so a retry never
// re-sends them.
func (a *Agent) sendRange(ctx context.Context, b *spool.Batch, lo, hi int) error {
	_, err := a.client.PostEvents(ctx, transport.GzipLines(b.Lines[lo:hi]))
	switch {
	case err == nil:
		b.Commit(hi)
		a.sent.Add(uint64(hi - lo))
		return nil
	case transport.IsStatus(err, 413):
		if hi-lo == 1 {
			a.log.Warn("dropping event the server considers too large", "bytes", len(b.Lines[lo]))
			b.Commit(hi)
			a.dropped.Add(1)
			return nil
		}
		mid := (lo + hi) / 2
		if err := a.sendRange(ctx, b, lo, mid); err != nil {
			return err
		}
		return a.sendRange(ctx, b, mid, hi)
	case !transport.Retryable(err):
		a.log.Error("server rejected an event batch; dropping it", "events", hi-lo, "err", err)
		b.Commit(hi)
		a.dropped.Add(uint64(hi - lo))
		return nil
	}
	return err
}

func (a *Agent) commandLoop(ctx context.Context) {
	var bo backoff.Backoff
	for ctx.Err() == nil {
		cmds, err := a.client.PollCommands(ctx, api.DefaultLongPoll)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Debug("command poll failed", "err", err)
			bo.Sleep(ctx)
			continue
		}
		bo.Reset()
		for _, sc := range cmds {
			a.handler.Handle(ctx, sc)
		}
		// Drain a pending poke; the next long-poll starts immediately anyway.
		select {
		case <-a.pollNow:
		default:
		}
	}
}

func (a *Agent) flushLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.spool.Flush(); err != nil {
				a.log.Warn("flush spool", "err", err)
			}
		}
	}
}

// --- status file for `homexdr-agent status` ---

// RuntimeStatus is written to status.json by the running agent.
type RuntimeStatus struct {
	AgentID            string            `json:"agent_id"`
	PID                int               `json:"pid"`
	UpdatedAt          time.Time         `json:"updated_at"`
	Server             string            `json:"server"`
	LastHeartbeat      time.Time         `json:"last_heartbeat,omitzero"`
	LastHeartbeatError string            `json:"last_heartbeat_error,omitempty"`
	Status             api.AgentStatus   `json:"status"`
	Counters           map[string]uint64 `json:"counters,omitempty"`
}

func (a *Agent) writeStatus() {
	if a.spool == nil || a.sup == nil {
		return
	}
	acc, filt, failed := a.pipe.Counters()
	a.hbMu.Lock()
	rs := RuntimeStatus{
		AgentID: a.id.AgentID, PID: os.Getpid(), UpdatedAt: time.Now().UTC(), Server: a.local.ServerURL,
		LastHeartbeat: a.lastHB, LastHeartbeatError: a.lastHBEr, Status: a.status(),
		Counters: map[string]uint64{"spooled": acc, "filtered": filt, "spool_errors": failed},
	}
	a.hbMu.Unlock()
	_ = fsutil.WriteJSONAtomic(filepath.Join(a.dataDir, StatusFile), rs, 0o600)
}

// ReadStatus reads the status file of a (possibly running) agent.
func ReadStatus(dataDir string) (RuntimeStatus, error) {
	var rs RuntimeStatus
	err := fsutil.ReadJSON(filepath.Join(dataDir, StatusFile), &rs)
	return rs, err
}

// MergeCollectors returns the platform collectors plus the cross-platform ones.
func MergeCollectors(p platform.Platform, env platform.Env) map[string]platform.Collector {
	m := maps.Clone(p.Collectors(env))
	if m == nil {
		m = map[string]platform.Collector{}
	}
	if _, ok := m["file.find"]; !ok {
		m["file.find"] = collect.FileFind
	}
	return m
}
