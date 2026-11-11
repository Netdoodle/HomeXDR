//go:build windows

package windows

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Turning Sysmon and Security records into ECS process events.

const (
	sysmonChannel   = "Microsoft-Windows-Sysmon/Operational"
	securityChannel = "Security"

	sysmonQuery   = "*[System[(EventID=1 or EventID=5)]]"
	securityQuery = "*[System[(EventID=4688 or EventID=4689)]]"

	// startWindow is how long before an event a live process's creation time may be
	// for the process to count as the one the event describes. Anything older is a
	// different process that reused the PID.
	startWindow = 5 * time.Second
	// startAhead allows for event times that are rounded down (Sysmon's UtcTime has
	// millisecond precision).
	startAhead = 100 * time.Millisecond

	sweepInterval = 10 * time.Second
	// reapInterval is how often running entries are checked against the live
	// processes, for exits that are never logged ("Audit Process Termination" off, or
	// a Sysmon configuration that filters event 5).
	reapInterval = time.Minute
)

// procMapper converts records to events and keeps the process table.
type procMapper struct {
	env       platform.Env
	src       procSource
	table     *procTable
	users     *userCache
	pe        func(path string) *event.PE // nil: no version lookups
	now       func() time.Time
	lastSweep time.Time
	lastReap  time.Time

	// origins caches each process's lineage (lineage.go), by entity ID.
	lineMu  sync.Mutex
	origins map[string]origin
}

func newProcMapper(env platform.Env, src procSource, pe func(string) *event.PE) *procMapper {
	return &procMapper{env: env, src: src, table: newProcTable(procTableMax), users: newUserCache(), pe: pe, now: time.Now, origins: map[string]origin{}}
}

// loadSnapshot fills the table with the running processes and returns how many it
// added. It emits nothing, like the Linux sensor at startup.
func (m *procMapper) loadSnapshot() (int, error) {
	pairs, err := m.src.list()
	type item struct {
		pair procPair
		lp   *liveProc
	}
	items := make(map[int64]item, len(pairs))
	for _, p := range pairs {
		if lp, ok := m.src.open(p.PID, wantDetails); ok {
			items[p.PID] = item{p, lp}
		}
	}
	for pid, it := range items {
		start := it.lp.createdAt()
		key := filetimeKey(it.lp.Created)
		e := &procEntry{
			PID: pid, PPID: it.pair.PPID, Key: key, EntityID: m.env.EntityID(pid, key), Start: start,
			Executable: it.lp.Executable, CommandLine: it.lp.CommandLine, User: m.users.user(it.lp.UserSID),
		}
		e.Name = baseName(e.Executable)
		if e.Name == "" {
			e.Name = it.pair.Name
		}
		// The PPID may belong to a newer process by now: only a parent created before
		// the child is the real one.
		if par, ok := items[it.pair.PPID]; ok && it.pair.PPID != pid &&
			(!par.lp.createdAt().After(start) || (m.clockSetBack(par.lp.createdAt()) && !m.clockSetBack(start))) {
			e.ParentEntityID = m.env.EntityID(it.pair.PPID, filetimeKey(par.lp.Created))
		}
		m.table.put(e)
	}
	return len(items), err
}

// handle converts one record; it returns nil for records that are not process events
// or cannot be attributed.
func (m *procMapper) handle(r *Record) *event.Event {
	now := m.now()
	if m.lastReap.IsZero() {
		m.lastReap = now
	}
	if now.Sub(m.lastReap) > reapInterval {
		m.lastReap = now
		m.reap(now)
	}
	if now.Sub(m.lastSweep) > sweepInterval {
		m.lastSweep = now
		m.table.sweep()
	}
	switch {
	case isSysmon(r):
		switch r.EventID {
		case 1:
			ev := m.sysmonStart(r)
			m.labelLineage(ev)
			return ev
		case 5:
			return m.sysmonExit(r)
		}
	case isSecurity(r):
		switch r.EventID {
		case 4688:
			ev := m.securityStart(r)
			m.labelLineage(ev)
			return ev
		case 4689:
			return m.securityExit(r)
		}
	}
	return nil
}

// reap marks running entries as exited when their process is gone or its PID now
// belongs to another process. Entries younger than exitLinger are left alone, so an
// exit event that is merely late still finds its process.
func (m *procMapper) reap(now time.Time) {
	for _, e := range m.table.running() {
		if now.Sub(e.Start) < exitLinger {
			continue
		}
		lp, ok := m.src.open(e.PID, 0)
		if ok {
			ct := lp.createdAt()
			// Keys taken from event times are close to, not equal to, the real one.
			if filetimeKey(lp.Created) == e.Key || (ct.Sub(e.Start) < timeSlack && e.Start.Sub(ct) < timeSlack) {
				continue
			}
		}
		m.table.exit(e, now)
	}
}

func isSysmon(r *Record) bool {
	return strings.EqualFold(r.Channel, sysmonChannel) || strings.EqualFold(r.Provider, "Microsoft-Windows-Sysmon")
}

func isSecurity(r *Record) bool {
	return strings.EqualFold(r.Channel, securityChannel) || strings.EqualFold(r.Provider, "Microsoft-Windows-Security-Auditing")
}

// startKey picks the entity ID start key for a process the event says was created at
// about created. A process object with this PID created within startWindow before
// the event is the one the event describes: its exact creation time is the key, and
// its details are returned. Otherwise (it exited, or the PID was reused) the event's
// time stands in for the creation time.
func (m *procMapper) startKey(pid int64, created time.Time, want detailFlags) (uint64, time.Time, *liveProc) {
	if lp, ok := m.src.open(pid, want); ok {
		ct := lp.createdAt()
		if !ct.Before(created.Add(-startWindow)) && !ct.After(created.Add(startAhead)) {
			return filetimeKey(lp.Created), ct, lp
		}
	}
	return timeToFiletimeKey(created), created, nil
}

// lookup finds the table entry for a process that was alive at time at, asking the
// live process when the table has none. image is the executable the event names for
// it, if any.
//
// A process whose recorded start is later than at is normally a newer one that reused
// the PID. But the clock may have been set back since it started: a PC that boots with
// the hardware clock read as local time and is then corrected by NTP leaves every
// process started at boot with a creation time hours in the future. So such a process
// is still accepted when its executable is the one the event names, or when its start
// is later than now (see clockSetBack).
func (m *procMapper) lookup(pid int64, guid string, at time.Time, image string) *procEntry {
	if pid <= 0 {
		return nil
	}
	if e := m.table.getGUID(guid); e != nil {
		return e
	}
	if e := m.table.get(pid, at); e != nil {
		return e
	}
	if e := m.table.getRunning(pid); e != nil && (sameImage(e.Executable, image) || m.clockSetBack(e.Start)) {
		return e
	}
	// Not in the table (the snapshot could not open it, or it started while the
	// sensor was switching sources). Accept the live process only if it already
	// existed at time at.
	lp, ok := m.src.open(pid, wantDetails)
	if !ok || (lp.createdAt().After(at.Add(timeSlack)) && !sameImage(lp.Executable, image) && !m.clockSetBack(lp.createdAt())) {
		return nil
	}
	key := filetimeKey(lp.Created)
	e := &procEntry{
		PID: pid, Key: key, EntityID: m.env.EntityID(pid, key), Start: lp.createdAt(),
		Executable: lp.Executable, Name: baseName(lp.Executable), CommandLine: lp.CommandLine,
		User: m.users.user(lp.UserSID),
	}
	m.table.put(e)
	return e
}

// parent describes the parent of a process created at childStart. Fields the event
// carries itself are filled in by the caller.
func (m *procMapper) parent(ppid int64, guid string, childStart time.Time, image string) (*event.Process, *procEntry) {
	if ppid <= 0 {
		return nil, nil
	}
	p := &event.Process{PID: ppid}
	e := m.lookup(ppid, guid, childStart, image)
	if e != nil {
		p.EntityID, p.Name, p.Executable, p.CommandLine = e.EntityID, e.Name, e.Executable, e.CommandLine
		if e.User != nil {
			u := *e.User
			p.User = &u
		}
	}
	return p, e
}

// sysmonStart maps Sysmon event 1 (process creation).
func (m *procMapper) sysmonStart(r *Record) *event.Event {
	d := r.Data
	pid := parsePID(d["ProcessId"])
	if pid <= 0 {
		return nil
	}
	created := parseSysmonTime(d["UtcTime"])
	if created.IsZero() {
		created = recordTime(r)
	}
	key, start, lp := m.startKey(pid, created, wantDetails)
	exe := clean(d["Image"])
	il := integrityFromName(d["IntegrityLevel"])
	p := &event.Process{
		EntityID:         m.env.EntityID(pid, key),
		PID:              pid,
		Name:             baseName(exe),
		Executable:       exe,
		CommandLine:      noDash(d["CommandLine"]),
		WorkingDirectory: clean(d["CurrentDirectory"]),
		Start:            &start,
		User:             accountUser(d["User"]),
		IntegrityLevel:   il,
		Elevated:         elevation("", il),
	}
	hash, imphash := parseHashes(d["Hashes"])
	p.Hash = hash
	pe := event.PE{
		OriginalFileName: cleanPE(d["OriginalFileName"]),
		Company:          cleanPE(d["Company"]),
		Product:          cleanPE(d["Product"]),
		Description:      cleanPE(d["Description"]),
		FileVersion:      cleanPE(d["FileVersion"]),
		Imphash:          imphash,
	}
	if pe != (event.PE{}) {
		p.PE = &pe
	}
	if s, err := strconv.ParseInt(strings.TrimSpace(d["TerminalSessionId"]), 10, 64); err == nil {
		p.SessionID = s
	}
	if lp != nil {
		switch {
		case p.User != nil && lp.UserSID != "":
			p.User.ID = lp.UserSID
		case p.User == nil:
			p.User = m.users.user(lp.UserSID)
		}
		if p.CommandLine == "" {
			p.CommandLine = lp.CommandLine
		}
	}
	ppid := parsePID(d["ParentProcessId"])
	parent, _ := m.parent(ppid, clean(d["ParentProcessGuid"]), start, clean(d["ParentImage"]))
	if parent != nil {
		if v := clean(d["ParentImage"]); v != "" {
			parent.Executable, parent.Name = v, baseName(v)
		}
		if v := noDash(d["ParentCommandLine"]); v != "" {
			parent.CommandLine = v
		}
		if u := accountUser(d["ParentUser"]); u != nil {
			if parent.User != nil && parent.User.ID != "" && strings.EqualFold(parent.User.Name, u.Name) {
				u.ID = parent.User.ID
			}
			parent.User = u
		}
	}
	p.Parent = parent
	m.remember(p, key, ppid, clean(d["ProcessGuid"]))
	return m.startEvent(r, p, logonID(d["LogonId"]))
}

// sysmonExit maps Sysmon event 5 (process terminated).
func (m *procMapper) sysmonExit(r *Record) *event.Event {
	d := r.Data
	pid := parsePID(d["ProcessId"])
	ended := parseSysmonTime(d["UtcTime"])
	if ended.IsZero() {
		ended = recordTime(r)
	}
	e := m.lookup(pid, clean(d["ProcessGuid"]), ended, clean(d["Image"]))
	if e == nil {
		return nil // started before the sensor saw it and already gone: no reliable entity ID
	}
	m.table.exit(e, ended)
	p := m.exitProcess(e, ended)
	if v := clean(d["Image"]); v != "" {
		p.Executable, p.Name = v, baseName(v)
	}
	if u := accountUser(d["User"]); u != nil {
		if p.User != nil && strings.EqualFold(p.User.Name, u.Name) {
			u.ID = p.User.ID
		}
		p.User = u
	}
	return m.exitEvent(r, p, "")
}

// securityStart maps Security event 4688 (a new process has been created). What the
// record lacks (working directory, version resource, session, the parent's command
// line, and the command line when auditing leaves it out) comes from the live process
// and the process table.
func (m *procMapper) securityStart(r *Record) *event.Event {
	d := r.Data
	pid := parsePID(d["NewProcessId"])
	if pid <= 0 {
		return nil
	}
	created := recordTime(r)
	key, start, lp := m.startKey(pid, created, wantDetails|wantCwd)
	exe := clean(d["NewProcessName"])
	il := integrityFromSID(d["MandatoryLabel"])
	user, logon := securityUser(d)
	p := &event.Process{
		EntityID:       m.env.EntityID(pid, key),
		PID:            pid,
		Name:           baseName(exe),
		Executable:     exe,
		CommandLine:    noDash(d["CommandLine"]),
		Start:          &start,
		User:           user,
		IntegrityLevel: il,
		Elevated:       elevation(d["TokenElevationType"], il),
	}
	if lp != nil {
		if p.CommandLine == "" {
			p.CommandLine = lp.CommandLine
		}
		if p.Executable == "" {
			p.Executable, p.Name = lp.Executable, baseName(lp.Executable)
		}
		p.WorkingDirectory = lp.WorkingDirectory
		if lp.HasSession {
			p.SessionID = lp.SessionID
		}
	}
	if m.pe != nil {
		p.PE = m.pe(p.Executable)
	}
	ppid := parsePID(d["ProcessId"])
	parent, _ := m.parent(ppid, "", start, clean(d["ParentProcessName"]))
	if parent != nil {
		if v := clean(d["ParentProcessName"]); v != "" {
			parent.Executable, parent.Name = v, baseName(v)
		}
	}
	p.Parent = parent
	m.remember(p, key, ppid, "")
	return m.startEvent(r, p, logon)
}

// securityExit maps Security event 4689 (a process has exited).
func (m *procMapper) securityExit(r *Record) *event.Event {
	d := r.Data
	pid := parsePID(d["ProcessId"])
	ended := recordTime(r)
	e := m.lookup(pid, "", ended, clean(d["ProcessName"]))
	if e == nil {
		return nil
	}
	m.table.exit(e, ended)
	p := m.exitProcess(e, ended)
	if v := clean(d["ProcessName"]); v != "" {
		p.Executable, p.Name = v, baseName(v)
	}
	if u := makeUser(d["SubjectUserSid"], d["SubjectUserName"], d["SubjectDomainName"]); u != nil {
		p.User = u
	}
	if code, ok := parseHexUint(d["Status"]); ok {
		c := int64(uint32(code))
		p.ExitCode = &c
	}
	return m.exitEvent(r, p, logonID(d["SubjectLogonId"]))
}

// remember stores a started process in the table.
func (m *procMapper) remember(p *event.Process, key uint64, ppid int64, guid string) {
	e := &procEntry{
		PID: p.PID, PPID: ppid, Key: key, EntityID: p.EntityID, Start: *p.Start,
		Name: p.Name, Executable: p.Executable, CommandLine: p.CommandLine, SysmonGUID: guid,
	}
	if p.User != nil {
		u := *p.User
		e.User = &u
	}
	if p.Parent != nil {
		e.ParentEntityID = p.Parent.EntityID
	}
	m.table.put(e)
}

func (m *procMapper) exitProcess(e *procEntry, ended time.Time) *event.Process {
	start := e.Start
	p := &event.Process{
		EntityID: e.EntityID, PID: e.PID, Name: e.Name, Executable: e.Executable,
		CommandLine: e.CommandLine, Start: &start, End: &ended,
	}
	if e.User != nil {
		u := *e.User
		p.User = &u
	}
	return p
}

func (m *procMapper) startEvent(r *Record, p *event.Process, logon string) *event.Event {
	desc := p.CommandLine
	if desc == "" {
		desc = p.Executable
	}
	return &event.Event{
		Timestamp: recordTime(r),
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeStart},
			Action: "exec", Outcome: event.OutcomeSuccess, Module: event.ModuleEventLog, Dataset: "process",
			Provider: r.Provider, Code: strconv.FormatUint(uint64(r.EventID), 10),
		},
		Message: "process started: " + desc,
		Process: p,
		Data:    winlogData(r, logon),
	}
}

func (m *procMapper) exitEvent(r *Record, p *event.Process, logon string) *event.Event {
	return &event.Event{
		Timestamp: recordTime(r),
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryProcess}, Type: []string{event.TypeEnd},
			Action: "exit", Module: event.ModuleEventLog, Dataset: "process",
			Provider: r.Provider, Code: strconv.FormatUint(uint64(r.EventID), 10),
		},
		Message: "process exited: " + p.Name,
		Process: p,
		Data:    winlogData(r, logon),
	}
}

// winlogData records where the event came from, under the names Winlogbeat uses.
func winlogData(r *Record, logon string) map[string]any {
	d := map[string]any{"winlog.channel": r.Channel, "winlog.record_id": r.RecordID}
	if logon != "" {
		d["winlog.logon_id"] = logon
	}
	return d
}

func recordTime(r *Record) time.Time {
	if r.TimeCreated.IsZero() {
		return time.Now().UTC()
	}
	return r.TimeCreated
}

// securityUser picks the account a 4688 process runs as: the target account when the
// process was started for another user, otherwise the subject (the creator's account).
// It also returns the matching logon ID.
func securityUser(d map[string]string) (*event.User, string) {
	sid, name := clean(d["TargetUserSid"]), clean(d["TargetUserName"])
	if sid != "" && sid != "S-1-0-0" && name != "" {
		return makeUser(sid, name, d["TargetDomainName"]), logonID(d["TargetLogonId"])
	}
	return makeUser(d["SubjectUserSid"], d["SubjectUserName"], d["SubjectDomainName"]), logonID(d["SubjectLogonId"])
}

// makeUser builds a User from a SID, name and domain as Security events report them.
func makeUser(sid, name, domain string) *event.User {
	sid, name, domain = clean(sid), clean(name), clean(domain)
	if sid == "S-1-0-0" {
		sid = ""
	}
	if n, dm, ok := wellKnownUser(sid); ok {
		name, domain = n, dm
	}
	if sid == "" && name == "" {
		return nil
	}
	return &event.User{ID: sid, Name: name, Domain: domain}
}

// accountUser splits "DOMAIN\name" as Sysmon reports it.
func accountUser(s string) *event.User {
	s = clean(s)
	if s == "" {
		return nil
	}
	if dom, name, ok := strings.Cut(s, `\`); ok {
		return &event.User{Name: name, Domain: dom}
	}
	return &event.User{Name: s}
}

// integrityFromSID maps a mandatory label SID (S-1-16-<level>) to a level name.
func integrityFromSID(s string) string {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(strings.ToUpper(s), "S-1-16-")
	if !ok {
		return ""
	}
	v, err := strconv.ParseUint(rest, 10, 32)
	if err != nil {
		return ""
	}
	switch {
	case v >= 0x4000: // 16384 system, 20480 protected process
		return "system"
	case v >= 0x3000: // 12288
		return "high"
	case v >= 0x2000: // 8192 medium, 8448 medium plus
		return "medium"
	case v >= 0x1000: // 4096
		return "low"
	}
	return "untrusted"
}

// integrityFromName maps Sysmon's IntegrityLevel field to a level name.
func integrityFromName(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "untrusted":
		return "untrusted"
	case "low", "appcontainer":
		return "low"
	case "medium", "mediumplus", "medium plus":
		return "medium"
	case "high":
		return "high"
	case "system", "protected":
		return "system"
	}
	return integrityFromSID(s)
}

// elevation derives process.elevated from 4688's TokenElevationType and the integrity
// level. %%1937 (full token of a split admin) is elevated and %%1938 (limited token) is
// not. %%1936 is a token without a split (UAC off, the built-in Administrator, SYSTEM
// and services, and standard users alike), so its integrity level decides; the same
// rule applies when the type is unknown (Sysmon).
func elevation(tokenType, il string) *bool {
	var v bool
	switch strings.TrimSpace(tokenType) {
	case "%%1937":
		v = true
	case "%%1938":
		v = false
	default:
		if il == "" {
			return nil
		}
		v = il == "high" || il == "system"
	}
	return &v
}

// parseHashes parses Sysmon's "SHA1=..,MD5=..,SHA256=..,IMPHASH=.." field.
func parseHashes(s string) (*event.Hash, string) {
	var h event.Hash
	var imphash string
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "MD5":
			h.MD5 = v
		case "SHA1":
			h.SHA1 = v
		case "SHA256":
			h.SHA256 = v
		case "IMPHASH":
			imphash = v
		}
	}
	if h == (event.Hash{}) {
		return nil, imphash
	}
	return &h, imphash
}

// parseSysmonTime parses Sysmon's UtcTime ("2006-01-02 15:04:05.000", UTC).
func parseSysmonTime(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05.999999999", strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// parsePID parses a decimal PID (Sysmon) or a hex one with a 0x prefix (Security).
func parsePID(s string) int64 {
	s = strings.TrimSpace(s)
	if v, ok := parseHexUint(s); ok && strings.HasPrefix(strings.ToLower(s), "0x") {
		return int64(v)
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func parseHexUint(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	h, ok := strings.CutPrefix(strings.ToLower(s), "0x")
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(h, 16, 64)
	return v, err == nil
}

func logonID(s string) string { return strings.ToLower(clean(s)) }

// clean trims a value and maps the "-" placeholder to empty.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" {
		return ""
	}
	return s
}

// noDash maps the "-" placeholder to empty but keeps everything else as it is:
// command lines are compared exactly, trailing spaces included.
func noDash(s string) string {
	if strings.TrimSpace(s) == "-" {
		return ""
	}
	return s
}

// cleanPE also drops Sysmon's "?" for a missing version resource field.
func cleanPE(s string) string {
	s = clean(s)
	if s == "?" {
		return ""
	}
	return s
}

func baseName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

// clockSetBack reports a process start later than now. Only a clock set back since the
// process started produces one, so that process was already running at any earlier
// time and cannot be a newer one that reused the PID.
func (m *procMapper) clockSetBack(start time.Time) bool {
	return start.After(m.now().Add(timeSlack))
}

// sameImage reports whether two Win32 paths name the same executable. An empty path
// never matches.
func sameImage(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(a, b)
}
