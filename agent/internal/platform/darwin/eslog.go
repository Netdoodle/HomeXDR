package darwin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// eslogger (macOS 13+) is Apple's command-line Endpoint Security client. It prints one
// JSON object per event: the es_message_t, with the event's own fields under
// "event": {"<event name>": {...}}. Using it gives the agent Endpoint Security telemetry
// without the Apple-granted entitlement a custom ES client needs.

// esFile is es_file_t.
type esFile struct {
	Path          string `json:"path"`
	PathTruncated bool   `json:"path_truncated"`
}

// esToken is the part of audit_token_t that eslogger decodes.
type esToken struct {
	PID  int64  `json:"pid"`
	EUID uint32 `json:"euid"`
	RUID uint32 `json:"ruid"`
	ASID int64  `json:"asid"`
}

// esProcess is es_process_t.
type esProcess struct {
	AuditToken       esToken `json:"audit_token"`
	PPID             int64   `json:"ppid"`
	OriginalPPID     int64   `json:"original_ppid"`
	SessionID        int64   `json:"session_id"`
	SigningID        string  `json:"signing_id"`
	TeamID           string  `json:"team_id"`
	CDHash           string  `json:"cdhash"`
	CodesigningFlags int64   `json:"codesigning_flags"`
	IsPlatformBinary bool    `json:"is_platform_binary"`
	IsESClient       bool    `json:"is_es_client"`
	Executable       esFile  `json:"executable"`
	TTY              *esFile `json:"tty"`
	StartTime        string  `json:"start_time"`
}

// esMessage is es_message_t.
type esMessage struct {
	Time    string                     `json:"time"`
	Process esProcess                  `json:"process"`
	Event   map[string]json.RawMessage `json:"event"`
}

// parseESLine decodes one eslogger line and returns the event name and its fields.
func parseESLine(line []byte) (*esMessage, string, json.RawMessage, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return nil, "", nil, errors.New("not a JSON object")
	}
	var m esMessage
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, "", nil, err
	}
	for name, raw := range m.Event {
		return &m, name, raw, nil
	}
	return nil, "", nil, errors.New("no event")
}

// msgTime is the event's time, or now.
func (m *esMessage) msgTime() time.Time {
	if t, err := time.Parse(time.RFC3339Nano, m.Time); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

// startKey is the process start time in microseconds since the Unix epoch, the same
// value as kinfo_proc p_starttime (see event.ProcessEntityID).
func (p *esProcess) startKey() uint64 {
	t, err := time.Parse(time.RFC3339Nano, p.StartTime)
	if err != nil || t.UnixMicro() <= 0 {
		return 0
	}
	return uint64(t.UnixMicro())
}

// esUID decodes a uid that eslogger prints either as a number or as {"uid": n}.
type esUID struct {
	Set bool
	UID uint32
}

func (u *esUID) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '{' {
		var o struct {
			UID *uint32 `json:"uid"`
		}
		if err := json.Unmarshal(b, &o); err != nil {
			return err
		}
		if o.UID != nil {
			u.Set, u.UID = true, *o.UID
		}
		return nil
	}
	n, err := strconv.ParseUint(string(b), 10, 32)
	if err != nil {
		return err
	}
	u.Set, u.UID = true, uint32(n)
	return nil
}

// Code signing flags (cs_blobs.h).
const (
	csValid          = 0x00000001
	csAdhoc          = 0x00000002
	csPlatformBinary = 0x04000000
	csSigned         = 0x20000000
)

// codeSignature describes how a process image is signed.
func codeSignature(p *esProcess) *event.CodeSignature {
	f := uint32(p.CodesigningFlags)
	signed := f&csSigned != 0 || p.SigningID != ""
	cs := &event.CodeSignature{Exists: signed}
	if !signed {
		cs.Status = "unsigned"
		return cs
	}
	valid := f&csValid != 0
	trusted := valid && (p.IsPlatformBinary || f&csPlatformBinary != 0 || (p.TeamID != "" && f&csAdhoc == 0))
	cs.Valid, cs.Trusted = &valid, &trusted
	switch {
	case p.IsPlatformBinary || f&csPlatformBinary != 0:
		cs.Status, cs.SubjectName = "apple", "Apple"
	case f&csAdhoc != 0:
		cs.Status = "adhoc"
	case p.TeamID != "":
		cs.Status, cs.SubjectName = "developer", p.TeamID
	default:
		cs.Status = "signed"
	}
	return cs
}

// esMapper turns eslogger messages into events.
type esMapper struct {
	entity func(pid int64, start uint64) string
	// parent describes a process the mapper has not seen exec (started before the agent);
	// nil means no lookup.
	parent func(ppid int64) *event.Process
	user   func(uid uint32) string
	self   int64
	procs  *lru[string, procSummary]
	// skipped holds entity IDs of the agent's own children (lsof, launchctl, ...), so
	// their exits are not reported either.
	skipped *lru[string, bool]
}

func newESMapper(entity func(int64, uint64) string, parent func(int64) *event.Process, user func(uint32) string, self int64) *esMapper {
	if user == nil {
		user = func(uid uint32) string { return strconv.FormatUint(uint64(uid), 10) }
	}
	return &esMapper{entity: entity, parent: parent, user: user, self: self,
		procs: newLRU[string, procSummary](16384), skipped: newLRU[string, bool](1024)}
}

// proc describes an es_process_t (an instigator, a parent, the process making a change).
func (m *esMapper) proc(p *esProcess) *event.Process {
	if p == nil || p.AuditToken.PID == 0 && p.Executable.Path == "" {
		return nil
	}
	ep := &event.Process{
		PID: p.AuditToken.PID, Executable: p.Executable.Path, Name: baseName(p.Executable.Path),
		User: &event.User{ID: strconv.FormatUint(uint64(p.AuditToken.RUID), 10), Name: m.user(p.AuditToken.RUID)},
	}
	if k := p.startKey(); k != 0 {
		ep.EntityID = m.entity(ep.PID, k)
		if s, ok := m.procs.get(ep.EntityID); ok && s.CommandLine != "" {
			ep.CommandLine = s.CommandLine
		}
	}
	return ep
}

func (m *esMapper) meta(cat []string, typ []string, action, outcome, dataset string) event.Meta {
	return event.Meta{Kind: event.KindEvent, Category: cat, Type: typ, Action: action, Outcome: outcome,
		Module: event.ModuleESLogger, Dataset: dataset}
}

// mapProcess handles the process sensor's events. It returns nil for events it skips.
func (m *esMapper) mapProcess(msg *esMessage, name string, raw json.RawMessage) *event.Event {
	ts := msg.msgTime()
	switch name {
	case "exec":
		return m.exec(msg, raw, ts)
	case "exit":
		return m.exit(msg, raw, ts)
	case "btm_launch_item_add", "btm_launch_item_remove":
		return m.launchItem(name, raw, ts)
	case "xp_malware_detected", "xp_malware_remediated":
		return m.xprotect(name, raw, ts)
	case "gatekeeper_user_override":
		return m.gatekeeper(msg, raw, ts)
	case "tcc_modify":
		return m.tcc(raw, ts)
	case "profile_add", "profile_remove":
		return m.profile(name, raw, ts)
	}
	return nil
}

type esExec struct {
	Target esProcess `json:"target"`
	Args   []string  `json:"args"`
	Cwd    *esFile   `json:"cwd"`
	Script *esFile   `json:"script"`
}

func (m *esMapper) exec(msg *esMessage, raw json.RawMessage, ts time.Time) *event.Event {
	var x esExec
	if json.Unmarshal(raw, &x) != nil {
		return nil
	}
	t := &x.Target
	pid := t.AuditToken.PID
	key := t.startKey()
	if key == 0 {
		key = msg.Process.startKey()
	}
	id := m.entity(pid, key)
	if pid == m.self || t.PPID == m.self {
		m.skipped.put(id, true) // the agent's own commands
		return nil
	}
	exe := t.Executable.Path
	p := &event.Process{
		EntityID: id, PID: pid, Name: baseName(exe), Executable: exe,
		Args: x.Args, CommandLine: joinArgs(x.Args), CodeSignature: codeSignature(t),
		User: &event.User{ID: strconv.FormatUint(uint64(t.AuditToken.RUID), 10), Name: m.user(t.AuditToken.RUID)},
	}
	if len(x.Args) == 0 {
		p.CommandLine = exe
	}
	elevated := t.AuditToken.EUID == 0
	p.Elevated = &elevated
	if x.Cwd != nil {
		p.WorkingDirectory = x.Cwd.Path
	}
	if t.TTY != nil {
		p.TTY = t.TTY.Path
	}
	if st := startTimeFromMicros(key); !st.IsZero() {
		p.Start = &st
	}
	if t.PPID > 0 {
		if m.parent != nil {
			p.Parent = m.parent(t.PPID)
		}
		if p.Parent == nil {
			p.Parent = &event.Process{PID: t.PPID}
		}
		if p.Parent.EntityID != "" {
			if s, ok := m.procs.get(p.Parent.EntityID); ok {
				p.Parent.Name, p.Parent.Executable, p.Parent.CommandLine = s.Name, s.Executable, s.CommandLine
			}
		}
	}
	m.procs.put(id, procSummary{Name: p.Name, Executable: exe, CommandLine: p.CommandLine})
	data := map[string]any{}
	if t.SigningID != "" {
		data["signing_id"] = t.SigningID
	}
	if t.TeamID != "" {
		data["team_id"] = t.TeamID
	}
	if t.CDHash != "" {
		data["cdhash"] = t.CDHash
	}
	if x.Script != nil && x.Script.Path != "" {
		data["script"] = x.Script.Path
	}
	if t.OriginalPPID != 0 && t.OriginalPPID != t.PPID {
		data["original_ppid"] = t.OriginalPPID
	}
	ev := &event.Event{
		Timestamp: ts,
		Event:     m.meta([]string{event.CategoryProcess}, []string{event.TypeStart}, "exec", event.OutcomeSuccess, "process"),
		Message:   "process started: " + p.CommandLine,
		Process:   p,
	}
	if len(data) > 0 {
		ev.Data = data
	}
	return ev
}

func (m *esMapper) exit(msg *esMessage, raw json.RawMessage, ts time.Time) *event.Event {
	var x struct {
		Stat int64 `json:"stat"`
	}
	if json.Unmarshal(raw, &x) != nil {
		return nil
	}
	pr := &msg.Process
	key := pr.startKey()
	id := m.entity(pr.AuditToken.PID, key)
	if _, skip := m.skipped.get(id); skip || pr.AuditToken.PID == m.self || pr.PPID == m.self {
		m.skipped.remove(id)
		return nil
	}
	p := &event.Process{EntityID: id, PID: pr.AuditToken.PID, Name: baseName(pr.Executable.Path), Executable: pr.Executable.Path, End: &ts}
	if s, ok := m.procs.get(id); ok {
		p.Name, p.Executable, p.CommandLine = s.Name, s.Executable, s.CommandLine
		m.procs.remove(id)
	}
	if st := startTimeFromMicros(key); !st.IsZero() {
		p.Start = &st
	}
	code, sig := decodeExit(uint32(x.Stat))
	p.ExitCode = &code
	ev := &event.Event{
		Timestamp: ts,
		Event:     m.meta([]string{event.CategoryProcess}, []string{event.TypeEnd}, "exit", "", "process"),
		Message:   "process exited: " + p.Name,
		Process:   p,
	}
	if sig != 0 {
		ev.Data = map[string]any{"exit_signal": sig}
	}
	return ev
}

// btmItemTypes names es_btm_item_type_t.
var btmItemTypes = map[int]string{0: "user_item", 1: "app", 2: "login_item", 3: "agent", 4: "daemon"}

func (m *esMapper) launchItem(name string, raw json.RawMessage, ts time.Time) *event.Event {
	var x struct {
		Instigator     *esProcess `json:"instigator"`
		App            *esProcess `json:"app"`
		ExecutablePath string     `json:"executable_path"`
		Item           struct {
			ItemType int    `json:"item_type"`
			Legacy   bool   `json:"legacy"`
			Managed  bool   `json:"managed"`
			UID      uint32 `json:"uid"`
			ItemURL  string `json:"item_url"`
			AppURL   string `json:"app_url"`
		} `json:"item"`
	}
	if json.Unmarshal(raw, &x) != nil {
		return nil
	}
	typ, action, verb := event.TypeCreation, "launch_item_added", "added"
	if name == "btm_launch_item_remove" {
		typ, action, verb = event.TypeDeletion, "launch_item_removed", "removed"
	}
	path := fileURLPath(x.Item.ItemURL)
	kind := btmItemTypes[x.Item.ItemType]
	if kind == "" {
		kind = strconv.Itoa(x.Item.ItemType)
	}
	data := map[string]any{"item_type": kind, "legacy": x.Item.Legacy, "managed": x.Item.Managed,
		"uid": x.Item.UID, "item_url": x.Item.ItemURL}
	if x.ExecutablePath != "" {
		data["executable_path"] = x.ExecutablePath
	}
	if x.Item.AppURL != "" {
		data["app_path"] = fileURLPath(x.Item.AppURL)
	}
	ev := &event.Event{
		Timestamp: ts,
		Event:     m.meta([]string{event.CategoryConfiguration}, []string{typ}, action, event.OutcomeSuccess, "persistence"),
		Message:   fmt.Sprintf("launch %s %s: %s", strings.ReplaceAll(kind, "_", " "), verb, firstNonEmpty(path, x.ExecutablePath)),
		Data:      data,
		Process:   m.proc(firstProc(x.Instigator, x.App)),
		User:      &event.User{ID: strconv.FormatUint(uint64(x.Item.UID), 10), Name: m.user(x.Item.UID)},
	}
	if path != "" {
		ev.File = &event.File{Path: path, Name: baseName(path), Directory: dirName(path)}
	}
	return ev
}

func (m *esMapper) xprotect(name string, raw json.RawMessage, ts time.Time) *event.Event {
	var x map[string]any
	if json.Unmarshal(raw, &x) != nil {
		return nil
	}
	ident := str(x, "malware_identifier")
	data := map[string]any{"malware_identifier": ident, "signature_version": str(x, "signature_version"),
		"incident_identifier": str(x, "incident_identifier")}
	path := str(x, "detected_path")
	action, msg, outcome := "malware_detected", "XProtect detected "+ident, event.OutcomeSuccess
	if name == "xp_malware_remediated" {
		path = str(x, "remediated_path")
		action, msg = "malware_remediated", "XProtect remediated "+ident
		data["action_type"] = str(x, "action_type")
		data["result"] = str(x, "result_description")
		if ok, isBool := x["success"].(bool); isBool && !ok {
			outcome = event.OutcomeFailure
		}
	}
	ev := &event.Event{
		Timestamp: ts,
		Event:     m.meta([]string{event.CategoryMalware}, []string{event.TypeInfo}, action, outcome, "malware"),
		Message:   msg,
		Data:      data,
	}
	ev.Event.Provider = "XProtect"
	if path != "" {
		ev.Message += " in " + path
		ev.File = &event.File{Path: path, Name: baseName(path), Directory: dirName(path)}
	}
	return ev
}

func (m *esMapper) gatekeeper(msg *esMessage, raw json.RawMessage, ts time.Time) *event.Event {
	var x map[string]any
	if json.Unmarshal(raw, &x) != nil {
		return nil
	}
	// "file" is a path string or an es_file_t, depending on file_type.
	path := str(x, "file", "path")
	if path == "" {
		path = str(x, "file")
	}
	data := map[string]any{}
	if h := str(x, "sha256"); h != "" {
		data["sha256"] = h
	}
	for _, k := range []string{"signing_id", "team_id", "cdhash"} {
		if v := str(x, "signing_info", k); v != "" {
			data[k] = v
		}
	}
	ev := &event.Event{
		Timestamp: ts,
		Event:     m.meta([]string{event.CategoryConfiguration}, []string{event.TypeChange}, "gatekeeper_override", event.OutcomeSuccess, "gatekeeper"),
		Message:   "Gatekeeper overridden by the user for " + path,
		Process:   m.proc(&msg.Process),
		File:      &event.File{Path: path, Name: baseName(path), Directory: dirName(path)},
	}
	if len(data) > 0 {
		ev.Data = data
		if h, ok := data["sha256"].(string); ok {
			ev.File.Hash = &event.Hash{SHA256: h}
		}
	}
	return ev
}

func (m *esMapper) tcc(raw json.RawMessage, ts time.Time) *event.Event {
	var x map[string]any
	if json.Unmarshal(raw, &x) != nil {
		return nil
	}
	service := strings.TrimPrefix(str(x, "service"), "kTCCService")
	identity := str(x, "identity")
	data := map[string]any{"service": service, "identity": identity}
	for _, k := range []string{"right", "reason", "update_type", "identity_type"} {
		if v := str(x, k); v != "" {
			data[k] = v
		}
	}
	var inst *esProcess
	if b, err := json.Marshal(x["instigator"]); err == nil {
		var p esProcess
		if json.Unmarshal(b, &p) == nil && p.AuditToken.PID != 0 {
			inst = &p
		}
	}
	return &event.Event{
		Timestamp: ts,
		Event:     m.meta([]string{event.CategoryConfiguration}, []string{event.TypeChange}, "tcc_modified", event.OutcomeSuccess, "tcc"),
		Message:   fmt.Sprintf("privacy permission %s changed for %s", service, identity),
		Data:      data,
		Process:   m.proc(inst),
	}
}

func (m *esMapper) profile(name string, raw json.RawMessage, ts time.Time) *event.Event {
	var x struct {
		Instigator *esProcess     `json:"instigator"`
		IsUpdate   bool           `json:"is_update"`
		Profile    map[string]any `json:"profile"`
	}
	if json.Unmarshal(raw, &x) != nil {
		return nil
	}
	typ, action := event.TypeInstallation, "profile_installed"
	if name == "profile_remove" {
		typ, action = event.TypeDeletion, "profile_removed"
	} else if x.IsUpdate {
		typ, action = event.TypeChange, "profile_updated"
	}
	data := map[string]any{}
	for _, k := range []string{"identifier", "uuid", "display_name", "organization", "install_source", "scope"} {
		if v := str(x.Profile, k); v != "" {
			data[k] = v
		}
	}
	return &event.Event{
		Timestamp: ts,
		Event:     m.meta([]string{event.CategoryConfiguration}, []string{typ}, action, event.OutcomeSuccess, "profile"),
		Message:   strings.ReplaceAll(action, "_", " ") + ": " + firstNonEmpty(str(x.Profile, "display_name"), str(x.Profile, "identifier")),
		Data:      data,
		Process:   m.proc(x.Instigator),
	}
}

// ---- auth sensor ----

// sshResults names es_openssh_login_result_type_t.
var sshResults = map[int]string{
	0: "max_auth_tries", 1: "root_denied", 2: "success", 3: "none", 4: "password",
	5: "keyboard_interactive", 6: "publickey", 7: "hostbased", 8: "gssapi", 9: "invalid_user",
}

// authTypes names es_auth_type_t.
var authTypes = map[string]string{"od": "opendirectory", "touchid": "touchid", "token": "token", "auto_unlock": "auto_unlock"}

func (m *esMapper) authMeta(cats, types []string, action string, ok bool) event.Meta {
	outcome := event.OutcomeSuccess
	if !ok {
		outcome = event.OutcomeFailure
	}
	return m.meta(cats, types, action, outcome, "macos.auth")
}

// mapAuth handles the auth sensor's events. It returns nil for events it skips.
func (m *esMapper) mapAuth(msg *esMessage, name string, raw json.RawMessage) *event.Event {
	ts := msg.msgTime()
	authn := []string{event.CategoryAuthentication}
	session := []string{event.CategoryAuthentication, event.CategorySession}
	start, end := []string{event.TypeStart}, []string{event.TypeEnd}
	var x map[string]any
	if json.Unmarshal(raw, &x) != nil {
		return nil
	}
	success, _ := x["success"].(bool)
	uidOf := func(key string) *esUID {
		var u esUID
		if b, err := json.Marshal(x[key]); err == nil {
			_ = u.UnmarshalJSON(b)
		}
		return &u
	}
	user := func(name, uidKey string) *event.User {
		u := &event.User{Name: name}
		if id := uidOf(uidKey); id.Set {
			u.ID = strconv.FormatUint(uint64(id.UID), 10)
			if u.Name == "" {
				u.Name = m.user(id.UID)
			}
		}
		if u.Name == "" && u.ID == "" {
			return nil
		}
		return u
	}
	ev := &event.Event{Timestamp: ts}
	switch name {
	case "openssh_login":
		rt := int(num(x, "result_type"))
		cats := authn
		if success {
			cats = session
		}
		ev.Event = m.authMeta(cats, start, "ssh_login", success)
		ev.User = user(str(x, "username"), "uid")
		ev.Source = &event.Endpoint{IP: str(x, "source_address")}
		ev.Data = map[string]any{"result": sshResults[rt]}
		if rt == 0 {
			ev.Data["reason"] = "max_auth_tries"
		}
		if rt == 9 {
			ev.Data["invalid_user"] = true
		}
		ev.Message = fmt.Sprintf("ssh login %s for %s from %s", outcomeWord(success), str(x, "username"), str(x, "source_address"))
	case "openssh_logout":
		ev.Event = m.authMeta([]string{event.CategorySession}, end, "ssh_logout", true)
		ev.User = user(str(x, "username"), "uid")
		ev.Source = &event.Endpoint{IP: str(x, "source_address")}
		ev.Message = fmt.Sprintf("ssh logout for %s from %s", str(x, "username"), str(x, "source_address"))
	case "login_login":
		ev.Event = m.authMeta(session, start, "login", success)
		ev.User = user(str(x, "username"), "uid")
		if f := str(x, "failure_message"); f != "" {
			ev.Data = map[string]any{"reason": f}
		}
		ev.Message = fmt.Sprintf("login %s for %s", outcomeWord(success), str(x, "username"))
	case "login_logout":
		ev.Event = m.authMeta([]string{event.CategorySession}, end, "logout", true)
		ev.User = user(str(x, "username"), "uid")
		ev.Message = "logout for " + str(x, "username")
	case "lw_session_login", "lw_session_logout", "lw_session_lock", "lw_session_unlock":
		actions := map[string]string{"lw_session_login": "gui_login", "lw_session_logout": "gui_logout",
			"lw_session_lock": "screen_lock", "lw_session_unlock": "screen_unlock"}
		cats, typ := session, start
		switch name {
		case "lw_session_logout":
			cats, typ = []string{event.CategorySession}, end
		case "lw_session_lock":
			cats, typ = []string{event.CategorySession}, []string{event.TypeChange}
		}
		ev.Event = m.authMeta(cats, typ, actions[name], true)
		ev.User = user(str(x, "username"), "")
		ev.Data = map[string]any{"graphical_session_id": num(x, "graphical_session_id")}
		ev.Message = strings.ReplaceAll(actions[name], "_", " ") + ": " + str(x, "username")
	case "screensharing_attach":
		ev.Event = m.authMeta(session, start, "screensharing_login", success)
		ev.User = &event.User{Name: firstNonEmpty(str(x, "authentication_username"), str(x, "session_username"))}
		ev.Source = &event.Endpoint{IP: str(x, "source_address")}
		ev.Data = map[string]any{"viewer_appleid": str(x, "viewer_appleid"), "authentication_type": str(x, "authentication_type"),
			"session_username": str(x, "session_username"), "existing_session": x["existing_session"]}
		ev.Message = fmt.Sprintf("screen sharing %s from %s", outcomeWord(success), str(x, "source_address"))
	case "screensharing_detach":
		ev.Event = m.authMeta([]string{event.CategorySession}, end, "screensharing_logout", true)
		ev.Source = &event.Endpoint{IP: str(x, "source_address")}
		ev.Data = map[string]any{"viewer_appleid": str(x, "viewer_appleid")}
		ev.Message = "screen sharing ended from " + str(x, "source_address")
	case "authentication":
		data, _ := x["data"].(map[string]any)
		var kind string
		var detail map[string]any
		for k, v := range data {
			kind = k
			detail, _ = v.(map[string]any)
		}
		ev.Event = m.authMeta(authn, start, "authentication", success)
		name := firstNonEmpty(str(detail, "record_name"), str(detail, "username"))
		if name != "" {
			ev.User = &event.User{Name: name}
		} else if u := user("", "uid"); u != nil {
			ev.User = u
		}
		ev.Data = map[string]any{"auth_type": firstNonEmpty(authTypes[kind], kind)}
		for _, k := range []string{"record_type", "node_name", "touchid_mode", "kerberos_principal"} {
			if v := str(detail, k); v != "" {
				ev.Data[k] = v
			}
		}
		ev.Process = m.procFromAny(detail["instigator"])
		ev.Message = fmt.Sprintf("%s authentication %s for %s", ev.Data["auth_type"], outcomeWord(success), name)
	case "sudo":
		from, to := str(x, "from_username"), str(x, "to_username")
		if from == "" {
			if u := uidOf("from_uid"); u.Set {
				from = m.user(u.UID)
			}
		}
		if to == "" {
			to = "root"
			if u := uidOf("to_uid"); u.Set {
				to = m.user(u.UID)
			}
		}
		ev.Event = m.authMeta(authn, start, "sudo", success)
		ev.User = &event.User{Name: from, Target: &event.User{Name: to}}
		ev.Data = map[string]any{"command": str(x, "command")}
		if r := str(x, "reject_info", "failure_message"); r != "" {
			ev.Data["reason"] = r
			ev.Data["plugin"] = str(x, "reject_info", "plugin_name")
		}
		ev.Process = m.proc(&msg.Process)
		ev.Message = fmt.Sprintf("sudo %s: %s -> %s: %s", outcomeWord(success), from, to, str(x, "command"))
	case "su":
		from, to := str(x, "from_username"), str(x, "to_username")
		ev.Event = m.authMeta(authn, start, "su", success)
		ev.User = &event.User{Name: from, Target: &event.User{Name: to}}
		if f := str(x, "failure_message"); f != "" {
			ev.Data = map[string]any{"reason": f}
		}
		ev.Process = m.proc(&msg.Process)
		ev.Message = fmt.Sprintf("su %s: %s -> %s", outcomeWord(success), from, to)
	case "od_create_user", "od_delete_user", "od_disable_user", "od_enable_user", "od_modify_password",
		"od_create_group", "od_delete_group", "od_group_add", "od_group_remove":
		return m.directory(msg, name, x, ts)
	default:
		return nil
	}
	if ev.Process == nil && name != "openssh_login" && name != "openssh_logout" && name != "screensharing_attach" && name != "screensharing_detach" {
		ev.Process = m.proc(&msg.Process)
	}
	return ev
}

// directory maps the Open Directory account-management events (macOS 14+).
func (m *esMapper) directory(msg *esMessage, name string, x map[string]any, ts time.Time) *event.Event {
	ok := num(x, "error_code") == 0
	iam := []string{event.CategoryIAM}
	userT := func(t string) []string { return []string{event.TypeUser, t} }
	groupT := func(t string) []string { return []string{event.TypeGroup, t} }
	var types []string
	var action string
	target := firstNonEmpty(str(x, "user_name"), str(x, "account_name"))
	data := map[string]any{"node_name": str(x, "node_name")}
	switch name {
	case "od_create_user":
		types, action = userT(event.TypeCreation), "user_created"
	case "od_delete_user":
		types, action = userT(event.TypeDeletion), "user_deleted"
	case "od_disable_user":
		types, action = userT(event.TypeChange), "user_disabled"
	case "od_enable_user":
		types, action = userT(event.TypeChange), "user_enabled"
	case "od_modify_password":
		types, action = userT(event.TypeChange), "password_changed"
	case "od_create_group":
		types, action = groupT(event.TypeCreation), "group_created"
	case "od_delete_group":
		types, action = groupT(event.TypeDeletion), "group_deleted"
	case "od_group_add", "od_group_remove":
		types, action = groupT(event.TypeChange), "group_member_added"
		if name == "od_group_remove" {
			action = "group_member_removed"
		}
		target = firstNonEmpty(str(x, "member", "member_value", "name"), str(x, "member", "member_value", "uuid"), str(x, "member", "member_value"))
	}
	if g := str(x, "group_name"); g != "" {
		data["group"] = g
	}
	if code := num(x, "error_code"); code != 0 {
		data["error_code"] = code
	}
	inst := m.procFromAny(x["instigator"])
	if inst == nil {
		inst = m.proc(&msg.Process)
	}
	u := &event.User{}
	if inst != nil && inst.User != nil {
		u.Name, u.ID = inst.User.Name, inst.User.ID
	}
	if target != "" {
		u.Target = &event.User{Name: target}
	}
	ev := &event.Event{
		Timestamp: ts,
		Event:     m.authMeta(iam, types, action, ok),
		Message:   strings.ReplaceAll(action, "_", " ") + ": " + firstNonEmpty(target, str(x, "group_name")),
		User:      u,
		Data:      data,
		Process:   inst,
	}
	return ev
}

// procFromAny decodes an es_process_t that was decoded into a generic map.
func (m *esMapper) procFromAny(v any) *event.Process {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var p esProcess
	if json.Unmarshal(b, &p) != nil || p.AuditToken.PID == 0 {
		return nil
	}
	return m.proc(&p)
}

// ---- file sensor ----

// esFileChange is one file change from create, rename, unlink or close.
type esFileChange struct {
	Path, OldPath string
	Type, Action  string
}

// fileChange extracts the change from a file event. ok is false for events that are
// not changes (a close without writes).
func fileChange(name string, raw json.RawMessage) (c esFileChange, ok bool) {
	var x map[string]any
	if json.Unmarshal(raw, &x) != nil {
		return c, false
	}
	switch name {
	case "create":
		// destination is {"existing_file": es_file_t} or {"new_path": {"dir", "filename"}}.
		p := str(x, "destination", "existing_file", "path")
		if p == "" {
			if d := str(x, "destination", "new_path", "dir", "path"); d != "" {
				p = strings.TrimSuffix(d, "/") + "/" + str(x, "destination", "new_path", "filename")
			}
		}
		return esFileChange{Path: p, Type: event.TypeCreation, Action: "created"}, p != ""
	case "unlink":
		p := str(x, "target", "path")
		return esFileChange{Path: p, Type: event.TypeDeletion, Action: "deleted"}, p != ""
	case "rename":
		src := str(x, "source", "path")
		dst := str(x, "destination", "existing_file", "path")
		if dst == "" {
			if d := str(x, "destination", "new_path", "dir", "path"); d != "" {
				dst = strings.TrimSuffix(d, "/") + "/" + str(x, "destination", "new_path", "filename")
			}
		}
		return esFileChange{Path: dst, OldPath: src, Type: event.TypeChange, Action: "renamed"}, dst != ""
	case "close":
		if mod, _ := x["modified"].(bool); !mod {
			return c, false
		}
		p := str(x, "target", "path")
		return esFileChange{Path: p, Type: event.TypeChange, Action: "modified"}, p != ""
	}
	return c, false
}

// ---- helpers ----

// str walks nested maps and returns the value as a string ("" when missing).
func str(m map[string]any, keys ...string) string {
	var v any = m
	for _, k := range keys {
		mm, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = mm[k]
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func num(m map[string]any, key string) float64 {
	f, _ := m[key].(float64)
	return f
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstProc(ps ...*esProcess) *esProcess {
	for _, p := range ps {
		if p != nil && (p.AuditToken.PID != 0 || p.Executable.Path != "") {
			return p
		}
	}
	return nil
}

func outcomeWord(ok bool) string {
	if ok {
		return "succeeded"
	}
	return "failed"
}

func dirName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	if strings.HasPrefix(p, "/") {
		return "/"
	}
	return ""
}

// fileURLPath turns file:///Library/LaunchDaemons/x.plist into a path.
func fileURLPath(s string) string {
	if !strings.HasPrefix(s, "file://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		return strings.TrimPrefix(s, "file://")
	}
	return strings.TrimSuffix(u.Path, "/")
}
