// Command homexdr-agent is the HomeXDR endpoint agent.
//
//	homexdr-agent enroll    --server <url> --token <t> --ca-pin sha256:<hex> [--labels a,b] [--update-key ed25519:<b64>] [--insecure-tofu]
//	homexdr-agent install   [same flags]   enroll if needed, then install and start the service
//	homexdr-agent uninstall [--purge]      stop and remove the service (and, with --purge, all data)
//	homexdr-agent run                      run in the foreground (this is what the service runs)
//	homexdr-agent status                   show enrollment, service and runtime status
//	homexdr-agent version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/config"
	"github.com/Netdoodle/homexdr/agent/internal/core"
	"github.com/Netdoodle/homexdr/agent/internal/enroll"
	"github.com/Netdoodle/homexdr/agent/internal/identity"
	"github.com/Netdoodle/homexdr/agent/internal/osplatform"
	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/agent/internal/selfupdate"
	"github.com/Netdoodle/homexdr/agent/internal/spool"
	"github.com/Netdoodle/homexdr/agent/internal/state"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/version"
)

const usage = `homexdr-agent: HomeXDR endpoint agent

Usage:
  homexdr-agent enroll    --server <url> --token <token> --ca-pin sha256:<hex> [--labels a,b]
                          [--update-key ed25519:<base64>] [--data-dir <dir>] [--insecure-tofu] [--force]
  homexdr-agent install   [enroll flags]   enroll if needed, then install and start the service
  homexdr-agent uninstall [--purge]        stop and remove the service; --purge also deletes config and data
  homexdr-agent run                        run in the foreground (what the service runs)
  homexdr-agent status                     show enrollment, service and runtime status
  homexdr-agent version

Every command accepts --config <path> (default: %s, or $HOMEXDR_AGENT_CONFIG).
`

func main() {
	p := osplatform.Current()
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, p.Paths().ConfigFile)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "enroll":
		err = cmdEnroll(p, args)
	case "install":
		err = cmdInstall(p, args)
	case "uninstall":
		err = cmdUninstall(p, args)
	case "run":
		err = cmdRun(p, args)
	case "status":
		err = cmdStatus(p, args)
	case "version", "--version", "-v":
		fmt.Println("homexdr-agent", version.String())
	case "help", "-h", "--help":
		fmt.Printf(usage, p.Paths().ConfigFile)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, p.Paths().ConfigFile)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "homexdr-agent:", err)
		os.Exit(1)
	}
}

func defaultConfigPath(p platform.Platform) string {
	if v := os.Getenv("HOMEXDR_AGENT_CONFIG"); v != "" {
		return v
	}
	return p.Paths().ConfigFile
}

type enrollFlags struct {
	server, token, pin, labels, dataDir, updateKey string
	tofu, force                                    bool
}

func newFlags(p platform.Platform, name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfg := fs.String("config", defaultConfigPath(p), "path of the local config file")
	return fs, cfg
}

func addEnrollFlags(fs *flag.FlagSet) *enrollFlags {
	f := &enrollFlags{}
	fs.StringVar(&f.server, "server", "", "agent API URL, e.g. https://xdr.example.lan:8443")
	fs.StringVar(&f.token, "token", "", "enrollment token from the console")
	fs.StringVar(&f.pin, "ca-pin", "", "server CA pin, sha256:<hex> (console settings page)")
	fs.StringVar(&f.labels, "labels", "", "comma-separated host labels")
	fs.StringVar(&f.dataDir, "data-dir", "", "data directory (default: platform default)")
	fs.StringVar(&f.updateKey, "update-key", "", "release key, ed25519:<base64>; turns on signed automatic updates (local policy)")
	fs.BoolVar(&f.tofu, "insecure-tofu", false, "trust the server CA on first use when no --ca-pin is given")
	fs.BoolVar(&f.force, "force", false, "re-enroll even if already enrolled (creates a new host)")
	return f
}

func splitLabels(s string) []string {
	var out []string
	for _, l := range strings.Split(s, ",") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// enrolledID returns the agent ID if the config at cfgPath points at an enrolled data dir.
func enrolledID(p platform.Platform, cfgPath string) (config.Local, string, bool) {
	local, err := config.Load(cfgPath)
	if err != nil {
		return config.Local{}, "", false
	}
	dir := core.DataDir(local, p)
	if !identity.Exists(dir) {
		return local, "", false
	}
	b, err := os.ReadFile(filepath.Join(dir, identity.AgentIDFile))
	if err != nil {
		return local, "", false
	}
	return local, strings.TrimSpace(string(b)), true
}

func doEnroll(ctx context.Context, p platform.Platform, cfgPath string, f *enrollFlags) error {
	if f.server == "" || f.token == "" {
		return errors.New("--server and --token are required")
	}
	if f.pin != "" && !config.ValidPin(f.pin) {
		return errors.New("--ca-pin must look like sha256:<64 hex characters>")
	}
	if f.updateKey != "" {
		if _, err := api.ParseUpdateKey(f.updateKey); err != nil {
			return fmt.Errorf("--update-key: %w", err)
		}
	}
	_, oldID, enrolled := enrolledID(p, cfgPath)
	if enrolled && !f.force {
		return fmt.Errorf("already enrolled as agent %s (config %s); pass --force to re-enroll as a new host", oldID, cfgPath)
	}
	// Keep an existing config file (the operator's local policy); refuse to overwrite
	// one that does not parse.
	local := config.Default()
	if c, err := config.Load(cfgPath); err == nil {
		local = c
	} else if !errors.Is(err, config.ErrNotFound) {
		return fmt.Errorf("existing config is invalid, fix or remove it first: %w", err)
	}
	host := p.HostInfo(ctx)
	if host.OS.Platform == "" {
		host.OS.Platform = p.Name()
	}
	res, err := enroll.Enroll(ctx, enroll.Options{
		ServerURL: f.server, Token: f.token, CAPin: f.pin, InsecureTOFU: f.tofu,
		Labels: splitLabels(f.labels), Host: host,
	})
	if err != nil {
		return err
	}
	if f.pin == "" {
		fmt.Printf("WARNING: trusted the server CA on first use. Verify this pin against the console:\n  %s\n", res.Pin)
	}
	local.ServerURL = strings.TrimRight(f.server, "/")
	local.CAPin = res.Pin
	if f.updateKey != "" {
		local.UpdateKey, local.AutoUpdate = strings.TrimSpace(f.updateKey), true
	}
	if f.dataDir != "" {
		abs, err := filepath.Abs(f.dataDir)
		if err != nil {
			return err
		}
		local.DataDir = abs
	}
	dataDir := core.DataDir(local, p)
	if err := core.EnsurePrivateDir(p, dataDir); err != nil {
		return err
	}
	if enrolled {
		// A new identity: forget the old one's state and queued events.
		_ = identity.Remove(dataDir)
		_ = os.Remove(filepath.Join(dataDir, state.FileName))
		_ = os.RemoveAll(filepath.Join(dataDir, core.SpoolDir))
	}
	if err := res.Identity.Save(dataDir); err != nil {
		return fmt.Errorf("save identity: %w", err)
	}
	st, err := state.Open(filepath.Join(dataDir, state.FileName))
	if err != nil {
		return err
	}
	if err := st.SetConfig(res.Config); err != nil {
		return err
	}
	if err := config.Save(cfgPath, local); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if pp, ok := p.(platform.PathProtector); ok {
		if err := pp.ProtectPath(cfgPath); err != nil {
			return err
		}
	}
	fmt.Printf("enrolled as agent %s\n  server:  %s\n  config:  %s\n  data:    %s\n", res.Identity.AgentID, local.ServerURL, cfgPath, dataDir)
	return nil
}

func cmdEnroll(p platform.Platform, args []string) error {
	fs, cfg := newFlags(p, "enroll")
	f := addEnrollFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return doEnroll(ctx, p, *cfg, f)
}

func cmdInstall(p platform.Platform, args []string) error {
	fs, cfg := newFlags(p, "install")
	f := addEnrollFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfg != p.Paths().ConfigFile {
		return fmt.Errorf("install always uses the default config path %s (the service reads it)", p.Paths().ConfigFile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, id, ok := enrolledID(p, *cfg); ok && !f.force {
		fmt.Printf("already enrolled as agent %s\n", id)
	} else if err := doEnroll(ctx, p, *cfg, f); err != nil {
		return err
	}
	exe, err := core.Executable()
	if err != nil {
		return err
	}
	if err := p.Service().Install(exe); err != nil {
		if errors.Is(err, platform.ErrUnsupported) {
			return fmt.Errorf("service integration is %v; run `%s run` from your own supervisor", err, exe)
		}
		return fmt.Errorf("install service: %w", err)
	}
	st, _ := p.Service().Status()
	fmt.Printf("service installed (%s): %s run\n", st, exe)
	return nil
}

func cmdUninstall(p platform.Platform, args []string) error {
	fs, cfg := newFlags(p, "uninstall")
	purge := fs.Bool("purge", false, "also delete the config file and data directory (identity, spool, quarantine)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var errs []error
	if err := p.Service().Uninstall(); err != nil && !errors.Is(err, platform.ErrUnsupported) {
		errs = append(errs, fmt.Errorf("remove service: %w", err))
	} else if err == nil {
		fmt.Println("service stopped and removed")
	} else {
		fmt.Println("no service installed")
	}
	local, _ := config.Load(*cfg)
	dataDir := core.DataDir(local, p)
	// Never leave a host cut off: remove isolation rules even if the state says none.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	resp := p.Responder(platform.Env{DataDir: dataDir, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := resp.Release(ctx); err != nil {
		errs = append(errs, fmt.Errorf("release isolation: %w", err))
	} else if st, err := state.Open(filepath.Join(dataDir, state.FileName)); err == nil && st.Snapshot().Isolated {
		_ = st.SetIsolated(false, nil, nil)
		fmt.Println("host isolation released")
	}
	if *purge {
		if q := filepath.Join(dataDir, core.QuarantineDir); dirHasEntries(q) {
			fmt.Printf("note: deleting quarantined files in %s\n", q)
		}
		if err := os.RemoveAll(dataDir); err != nil {
			errs = append(errs, err)
		}
		if err := os.Remove(*cfg); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
		_ = os.Remove(filepath.Dir(*cfg)) // only succeeds if empty
		fmt.Printf("removed %s and %s\n", *cfg, dataDir)
	} else {
		fmt.Printf("kept %s and %s (use --purge to delete them)\n", *cfg, dataDir)
	}
	return errors.Join(errs...)
}

func dirHasEntries(dir string) bool {
	ents, err := os.ReadDir(dir)
	return err == nil && len(ents) > 0
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func cmdRun(p platform.Platform, args []string) error {
	fs, cfg := newFlags(p, "run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	local, err := config.Load(*cfg)
	if err != nil {
		return err
	}
	log := newLogger(local.LogLevel)
	slog.SetDefault(log)
	exe, err := core.Executable()
	if err != nil {
		return err
	}
	// An update that keeps crashing before it reaches the server is rolled back here.
	if restore, err := selfupdate.CheckStartup(core.DataDir(local, p), exe, version.Version, log); err != nil {
		log.Warn("update check", "err", err)
	} else if restore {
		return selfupdate.Exec(exe)
	}
	a, err := core.Load(p, *cfg, log)
	if err != nil {
		return err
	}
	handled, err := p.Service().RunAsService(a.Run)
	if handled {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = a.Run(ctx)
	if errors.Is(err, core.ErrRestart) {
		stop()
		return selfupdate.Exec(exe)
	}
	return err
}

func cmdStatus(p platform.Platform, args []string) error {
	fs, cfg := newFlags(p, "status")
	if err := fs.Parse(args); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "version:\t%s\n", version.String())
	fmt.Fprintf(w, "config:\t%s\n", *cfg)
	local, err := config.Load(*cfg)
	if err != nil {
		fmt.Fprintf(w, "enrolled:\tno (%v)\n", err)
		return nil
	}
	dataDir := core.DataDir(local, p)
	fmt.Fprintf(w, "data dir:\t%s\n", dataDir)
	fmt.Fprintf(w, "server:\t%s\n", local.ServerURL)
	fmt.Fprintf(w, "allowed actions:\t%s\n", strings.Join(local.AllowedActions, ", "))
	switch {
	case local.AutoUpdate && !selfupdate.Supported():
		fmt.Fprintf(w, "auto update:\ton in config, not supported on this platform\n")
	case local.AutoUpdate:
		fmt.Fprintf(w, "auto update:\ton (releases signed with %s)\n", local.UpdateKey)
	default:
		fmt.Fprintf(w, "auto update:\toff\n")
	}
	if id, err := identity.Load(dataDir); err == nil {
		c := id.Certificate()
		renew := c.NotAfter.Add(-c.NotAfter.Sub(c.NotBefore) / 3)
		fmt.Fprintf(w, "certificate:\texpires %s (renews automatically from %s)\n", c.NotAfter.Local().Format("2006-01-02"), renew.Local().Format("2006-01-02"))
	}
	if m, ok := selfupdate.Pending(dataDir); ok {
		fmt.Fprintf(w, "update:\t%s installed %s ago (from %s), not yet confirmed; %d start(s)\n",
			m.Version, time.Since(m.InstalledAt).Round(time.Second), m.PreviousVersion, m.Starts)
	}
	if _, id, ok := enrolledID(p, *cfg); ok {
		fmt.Fprintf(w, "enrolled:\tyes, agent %s\n", id)
	} else {
		fmt.Fprintf(w, "enrolled:\tno\n")
	}
	if s, err := p.Service().Status(); err == nil {
		fmt.Fprintf(w, "service:\t%s\n", s)
	} else {
		fmt.Fprintf(w, "service:\t%v\n", err)
	}
	if st, err := state.Open(filepath.Join(dataDir, state.FileName)); err == nil {
		snap := st.Snapshot()
		fmt.Fprintf(w, "isolated:\t%v\n", snap.Isolated)
		fmt.Fprintf(w, "central config:\tversion %d\n", snap.Config.Version)
	}
	qb, segs := spool.Inspect(filepath.Join(dataDir, core.SpoolDir))
	fmt.Fprintf(w, "spool:\t%d bytes queued in %d segments\n", qb, segs)
	rs, err := core.ReadStatus(dataDir)
	if err != nil {
		fmt.Fprintf(w, "runtime:\tno status yet (agent not running?)\n")
		return nil
	}
	fmt.Fprintf(w, "runtime:\tpid %d, updated %s ago\n", rs.PID, time.Since(rs.UpdatedAt).Round(time.Second))
	if !rs.LastHeartbeat.IsZero() {
		fmt.Fprintf(w, "last heartbeat:\t%s ago\n", time.Since(rs.LastHeartbeat).Round(time.Second))
	}
	if rs.LastHeartbeatError != "" {
		fmt.Fprintf(w, "heartbeat error:\t%s\n", rs.LastHeartbeatError)
	}
	fmt.Fprintf(w, "events:\t%d sent, %d queued, %d dropped\n", rs.Status.EventsSent, rs.Status.QueueEvents, rs.Status.EventsDropped)
	for _, s := range rs.Status.Sensors {
		line := fmt.Sprintf("%s (%s) %s, %d events", s.Name, s.Impl, s.State, s.Events)
		if s.Error != "" {
			line += ": " + s.Error
		}
		fmt.Fprintf(w, "sensor:\t%s\n", line)
	}
	return nil
}
