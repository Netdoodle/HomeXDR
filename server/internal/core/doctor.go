package core

// Doctor: a list of plain checks on whether this install is working, each with a suggested
// fix. The same checks back GET /api/doctor, the Data health page and `homexdr-server doctor`.
// See docs/health.md.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Check results.
const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
	CheckSkip = "skip" // does not apply to this install
)

const (
	doctorCheckTimeout = 20 * time.Second
	certWarnBefore     = 14 * 24 * time.Hour
	lowDiskFail        = 1 << 30
	lowDiskWarn        = 5 << 30
	syslogQuietAfter   = time.Hour
	runnerQuietAfter   = time.Hour
)

// CheckResult is one line of the doctor's report. Message and Fix never hold secrets.
type CheckResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// DoctorCheck is one check. Run fills in Status, Message and Fix.
type DoctorCheck struct {
	ID, Name string
	Run      func(ctx context.Context, c *Core) CheckResult
}

var doctorChecks []DoctorCheck

// RegisterDoctorCheck adds a check to the doctor. Call it from an init function in the
// feature's own file: func init() { RegisterDoctorCheck(DoctorCheck{...}) }.
func RegisterDoctorCheck(chk DoctorCheck) { doctorChecks = append(doctorChecks, chk) }

// DoctorReport is every check's result.
type DoctorReport struct {
	At      time.Time     `json:"at"`
	OK      int           `json:"ok"`
	Warn    int           `json:"warn"`
	Fail    int           `json:"fail"`
	Results []CheckResult `json:"results"`
}

// RunDoctor runs every check. A check that hangs reports a failure instead of holding up
// the others.
func (c *Core) RunDoctor(ctx context.Context) *DoctorReport {
	rep := &DoctorReport{At: time.Now().UTC(), Results: []CheckResult{}}
	for _, chk := range doctorChecks {
		r := c.runCheck(ctx, chk)
		r.ID, r.Name = chk.ID, chk.Name
		r.Message, r.Fix = c.scrub(r.Message), c.scrub(r.Fix)
		switch r.Status {
		case CheckOK:
			rep.OK++
		case CheckWarn:
			rep.Warn++
		case CheckFail:
			rep.Fail++
		}
		rep.Results = append(rep.Results, r)
	}
	return rep
}

func (c *Core) runCheck(ctx context.Context, chk DoctorCheck) CheckResult {
	cctx, cancel := context.WithTimeout(ctx, doctorCheckTimeout)
	defer cancel()
	done := make(chan CheckResult, 1)
	go func() { done <- chk.Run(cctx, c) }()
	select {
	case r := <-done:
		return r
	case <-cctx.Done():
		return CheckResult{Status: CheckFail, Message: "This check did not finish within " + doctorCheckTimeout.String() + "."}
	}
}

var urlCredentials = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@`)

// scrub removes anything that could be a secret from text that came from an error: a driver's
// message may quote the connection address, with its password.
func (c *Core) scrub(s string) string {
	if dsn := c.Cfg.ClickHouseDSN; dsn != "" {
		s = strings.ReplaceAll(s, dsn, "[event store address]")
	}
	return urlCredentials.ReplaceAllString(s, "${1}***@")
}

func checkOK(format string, a ...any) CheckResult {
	return CheckResult{Status: CheckOK, Message: fmt.Sprintf(format, a...)}
}

func checkSkip(format string, a ...any) CheckResult {
	return CheckResult{Status: CheckSkip, Message: fmt.Sprintf(format, a...)}
}

func checkWarn(fix, format string, a ...any) CheckResult {
	return CheckResult{Status: CheckWarn, Fix: fix, Message: fmt.Sprintf(format, a...)}
}

func checkFail(fix, format string, a ...any) CheckResult {
	return CheckResult{Status: CheckFail, Fix: fix, Message: fmt.Sprintf(format, a...)}
}

func init() {
	for _, chk := range []DoctorCheck{
		{"state_db", "Settings database", checkStateDB},
		{"event_store", "Event store", checkEventStore},
		{"disk", "Disk and retention", checkDisk},
		{"rules", "Detection rules", checkRules},
		{"rule_repos", "Rule repositories", checkRuleRepos},
		{"syslog", "Syslog intake", checkSyslog},
		{"agent_release", "Signed agent release", checkRelease},
		{"agents", "Agents", checkAgents},
		{"ai", "AI analyst", checkAI},
		{"feeds", "Data sources", checkFeeds},
	} {
		RegisterDoctorCheck(chk)
	}
}

func checkStateDB(ctx context.Context, c *Core) CheckResult {
	fix := "Check free disk space and file permissions on " + c.Cfg.DataDir + "."
	if err := c.State.Ping(ctx); err != nil {
		return checkFail(fix, "The settings database did not answer: %v", err)
	}
	if err := c.State.SetKV(ctx, "doctor_last_run", time.Now().UTC()); err != nil {
		return checkFail(fix, "The settings database cannot be written: %v", err)
	}
	return checkOK("Reachable and writable.")
}

// checkEventStore writes one small row and reads it back, the only honest test that events
// can be stored. It is a state event with its own dataset, not a telemetry source.
func checkEventStore(ctx context.Context, c *Core) CheckResult {
	fix := "Make sure the " + c.Cfg.EventStore + " event store is running and has free disk space, then check the server log."
	if err := c.Events.Ping(ctx); err != nil {
		return checkFail(fix, "The event store (%s) did not answer: %v", c.Cfg.EventStore, err)
	}
	now := time.Now().UTC()
	ev := &event.Event{
		ID: event.NewID(), Timestamp: now,
		Agent:   event.Agent{ID: ServerHostID, Type: event.AgentTypeIntegration},
		Host:    event.Host{ID: ServerHostID, Name: "HomeXDR"},
		Event:   event.Meta{Kind: event.KindState, Module: event.ModuleHomeXDR, Dataset: "homexdr.doctor", Ingested: &now},
		Message: "doctor write check",
	}
	if err := c.Events.Insert(ctx, []*event.Event{ev}); err != nil {
		return checkFail(fix, "The event store (%s) answers but cannot store events: %v", c.Cfg.EventStore, err)
	}
	got, err := events.SampleSource(ctx, c.Events, ServerHostID, event.ModuleHomeXDR, "homexdr.doctor", now.Add(-time.Minute), now.Add(time.Minute), 1)
	if err != nil {
		return checkFail(fix, "The event store (%s) stored a test row but could not read it back: %v", c.Cfg.EventStore, err)
	}
	if len(got) == 0 {
		return checkWarn(fix, "The event store (%s) accepted a test row but it could not be found right away.", c.Cfg.EventStore)
	}
	return checkOK("%s is reachable and writable.", c.Cfg.EventStore)
}

func checkDisk(ctx context.Context, c *Core) CheckResult {
	var parts []string
	status, fix := CheckOK, ""
	free, known := diskFree(c.Cfg.DataDir)
	if known {
		parts = append(parts, formatBytes(free)+" free on the data disk")
		switch {
		case free < lowDiskFail:
			status, fix = CheckFail, "Free up space on "+c.Cfg.DataDir+", or lower the retention settings."
		case free < lowDiskWarn:
			status, fix = CheckWarn, "Free up space on "+c.Cfg.DataDir+" soon, or lower the retention settings."
		}
	}
	size, err := c.Events.Size(ctx)
	if err != nil {
		parts = append(parts, "the size of the event store could not be read")
	} else {
		cap := "no size cap"
		if m := c.Cfg.RetentionMaxBytes; m > 0 {
			cap = "a cap of " + formatBytes(uint64(m))
			if float64(size) >= 0.95*float64(m) {
				parts = append(parts, "the event store is at its size cap, so the oldest events are being removed")
			}
		}
		parts = append(parts, fmt.Sprintf("events use %s with %s", formatBytes(uint64(max(size, 0))), cap))
	}
	if c.Cfg.RetentionDays > 0 {
		parts = append(parts, fmt.Sprintf("events are kept for %d days", c.Cfg.RetentionDays))
	} else {
		parts = append(parts, "events are kept with no time limit")
	}
	if c.Cfg.EventStore == "clickhouse" {
		parts = append(parts, "free space on ClickHouse's own disk is not checked here")
	}
	return CheckResult{Status: status, Fix: fix, Message: sentence(strings.Join(parts, "; "))}
}

func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func checkRules(_ context.Context, c *Core) CheckResult {
	total, enabled := c.Rules.Stats()
	errs := len(c.Rules.LoadErrors())
	switch {
	case enabled == 0:
		return checkWarn("Add a rule repository under Rules > Repositories, or enable some rules.", "%d rules loaded and none enabled, so nothing can fire.", total)
	case errs > enabled:
		return checkWarn("See the Rules page for which rules failed and why.", "%d rules enabled, but %d rule files failed to load.", enabled, errs)
	case errs > 0:
		return checkOK("%d of %d rules enabled. %d could not load, which is normal for large community rule sets: see the Rules page.", enabled, total, errs)
	}
	return checkOK("%d of %d rules enabled.", enabled, total)
}

func checkRuleRepos(ctx context.Context, c *Core) CheckResult {
	repos, err := c.State.ListRuleRepos(ctx)
	if err != nil {
		return checkFail("Check the server log.", "Could not read rule repositories: %v", err)
	}
	var active, problems []string
	newest := time.Time{}
	for _, r := range repos {
		if !r.Enabled {
			continue
		}
		active = append(active, r.Name)
		if r.CheckedAt != nil && r.CheckedAt.After(newest) {
			newest = *r.CheckedAt
		}
		switch {
		case r.Error != "":
			problems = append(problems, r.Name+": "+r.Error)
		case r.AutoUpdate && (r.CheckedAt == nil || time.Since(*r.CheckedAt) > 3*time.Duration(max(r.IntervalHours, 1))*time.Hour):
			problems = append(problems, r.Name+" has not checked for updates when it should have")
		}
	}
	if len(active) == 0 {
		return checkSkip("No rule repositories are in use.")
	}
	if len(problems) > 0 {
		return checkWarn("Open Rules > Repositories and run a check. A blocked download may need the host allowed on your firewall's DNS blocklist.", "%s", strings.Join(problems, "; "))
	}
	return checkOK("%d in use, last checked %s ago.", len(active), plainDuration(time.Since(newest)))
}

func checkSyslog(ctx context.Context, c *Core) CheckResult {
	if c.Cfg.SyslogAddr == "" {
		return checkSkip("The syslog listener is turned off (HOMEXDR_SYSLOG_ADDR is empty).")
	}
	hosts, err := c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostNetwork})
	if err != nil {
		return checkFail("Check the server log.", "Could not read hosts: %v", err)
	}
	fix := "Point your firewall's remote logging at this server, UDP or TCP port " + strings.TrimPrefix(c.Cfg.SyslogAddr, ":") + ", and check that HOMEXDR_SYSLOG_ALLOW lets it in."
	var newest *store.Host
	for _, h := range hosts {
		if h.LastSeen != nil && (newest == nil || h.LastSeen.After(*newest.LastSeen)) {
			newest = h
		}
	}
	if newest == nil {
		return checkWarn(fix, "Listening on %s, but nothing has ever sent logs.", c.Cfg.SyslogAddr)
	}
	since := time.Since(*newest.LastSeen)
	if since > syslogQuietAfter {
		return checkWarn(fix, "Nothing received for %s. Last from %s.", plainDuration(since), newest.Hostname)
	}
	return checkOK("Receiving logs from %s, %s ago.", newest.Hostname, plainDuration(since))
}

func checkRelease(_ context.Context, c *Core) CheckResult {
	st := c.Release.Status()
	if st.Signed {
		return checkOK("Version %s is signed, so agents can update themselves.", st.Version)
	}
	problem := st.Problem
	if problem == "" {
		problem = "no signed release"
	}
	return checkWarn("Agents keep running but will not update themselves. Run the release signing step on the server host. See docs/protocol.md.", "Agents cannot be offered an update: %s.", problem)
}

func checkAgents(ctx context.Context, c *Core) CheckResult {
	hosts, err := c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	if err != nil {
		return checkFail("Check the server log.", "Could not read hosts: %v", err)
	}
	rel := c.Release.Status().Version
	var expired, expiring, old, active []string
	now := time.Now()
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		active = append(active, h.Hostname)
		if h.CertExpires != nil {
			switch {
			case now.After(*h.CertExpires):
				expired = append(expired, h.Hostname)
			case h.CertExpires.Sub(now) < certWarnBefore:
				expiring = append(expiring, fmt.Sprintf("%s (in %s)", h.Hostname, plainDuration(h.CertExpires.Sub(now))))
			}
		}
		if rel != "" && h.AgentVersion != "" && h.AgentVersion != rel {
			old = append(old, h.Hostname+" runs "+h.AgentVersion)
		}
	}
	switch {
	case len(active) == 0:
		return checkSkip("No agents are enrolled.")
	case len(expired) > 0:
		return checkFail("Reinstall the agent with a new enrollment token on each of these hosts.", "Agent certificates have expired on: %s.", strings.Join(expired, ", "))
	case len(expiring) > 0:
		return checkWarn("Agents renew their own certificates. If this one stays, check that the agent is online and can reach the server.", "Agent certificates expire soon: %s.", strings.Join(expiring, ", "))
	case len(old) > 0:
		return checkWarn("See Settings > Agent updates, or use Update now on the host page.", "Not on this server's agent release (%s): %s.", rel, strings.Join(old, ", "))
	}
	return checkOK("%d %s, certificates valid, versions current.", len(active), plural(len(active), "agent", "agents"))
}

func checkAI(ctx context.Context, c *Core) CheckResult {
	set := c.Triage.Settings(ctx)
	if !set.Enabled {
		return checkSkip("The AI analyst is turned off.")
	}
	if ok, why := c.Triage.Ready(set); !ok {
		return checkWarn("Open Settings > AI analyst.", "The AI analyst is on, but cannot run: %s.", why)
	}
	if set.Engine != store.EngineMCP {
		return checkOK("Ready, using %s.", set.Provider)
	}
	if !c.Health.serving.Load() {
		return checkOK("Ready, using an MCP client. Only the running server knows when the runner last checked in; see this check on the Data health page.")
	}
	name, seen := c.Triage.Runner()
	switch {
	case seen.IsZero():
		return checkWarn("Start the MCP runner on the PC that has your Claude plan. See docs/ai-analyst.md.", "Ready, but no MCP runner has checked in since the server started.")
	case time.Since(seen) > runnerQuietAfter:
		return checkWarn("Check that the MCP runner is still running. See docs/ai-analyst.md.", "The MCP runner %s last checked in %s ago.", name, plainDuration(time.Since(seen)))
	}
	return checkOK("Ready. The MCP runner %s checked in %s ago.", name, plainDuration(time.Since(seen)))
}

func checkFeeds(ctx context.Context, c *Core) CheckResult {
	rep, err := c.Health.Feeds.Report(ctx)
	if err != nil {
		return checkFail("Check the server log.", "Could not read data sources: %v", err)
	}
	var silent []string
	never := 0
	for i := range rep.Sources {
		v := &rep.Sources[i]
		switch v.Status {
		case FeedSilent:
			silent = append(silent, v.Hostname+": "+v.Dataset)
		case FeedNeverSeen:
			never++
		}
	}
	const fix = "Open the Data health page for details on each source."
	if len(silent) > 0 {
		return checkWarn(fix, "Silent: %s.", strings.Join(silent, ", "))
	}
	if never > 0 {
		return checkWarn(fix, "%d expected %s never sent any data.", never, plural(never, "source has", "sources have"))
	}
	return checkOK("%d sources tracked, none silent.", len(rep.Sources))
}
