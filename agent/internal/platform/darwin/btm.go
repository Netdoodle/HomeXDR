package darwin

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
)

// Background Task Management (macOS 13+) records every login item, background task and
// launchd job the user can switch off under System Settings > General > Login Items.
// `sfltool dumpbtm` prints the database as text, grouped by user.

// BTM item types (the hex value after the type name).
const (
	btmApp            = 0x2
	btmLoginItem      = 0x4
	btmAgent          = 0x8
	btmDaemon         = 0x10
	btmDeveloper      = 0x20
	btmBackgroundTask = 0x2000
	btmLegacy         = 0x10000
)

// BTM disposition bits.
const (
	btmEnabled = 0x1
	btmAllowed = 0x2
)

// btmItem is one record of `sfltool dumpbtm`.
type btmItem struct {
	UID                                   int
	Name, Developer, TeamID, Identifier   string
	URL, ExecPath, BundleID, Parent, Used string
	Type, Disposition                     uint64
}

var (
	btmUIDRe  = regexp.MustCompile(`^Records for UID (-?\d+)\b`)
	btmItemRe = regexp.MustCompile(`^#\d+:$`)
	btmHexRe  = regexp.MustCompile(`\((0x[0-9a-fA-F]+)\)\s*$`)
)

// parseBTM parses `sfltool dumpbtm` output. Unknown lines are ignored, so new fields in
// later releases don't break it.
func parseBTM(b []byte) []btmItem {
	var out []btmItem
	uid := 0
	var cur *btmItem
	flush := func() {
		if cur != nil && cur.Identifier != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if m := btmUIDRe.FindStringSubmatch(line); m != nil {
			flush()
			uid, _ = strconv.Atoi(m[1])
			continue
		}
		if btmItemRe.MatchString(line) {
			// "#N:" alone starts an item; "#N: value" lines belong to a sub-list.
			flush()
			cur = &btmItem{UID: uid}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if strings.HasPrefix(k, "#") {
			continue // entry of a sub-list such as Embedded Item Identifiers
		}
		if v == "(null)" {
			v = ""
		}
		switch k {
		case "Name":
			cur.Name = v
		case "Developer Name":
			cur.Developer = v
		case "Team Identifier":
			cur.TeamID = v
		case "Type":
			cur.Type = btmHex(v)
		case "Disposition":
			cur.Disposition = btmHex(v)
		case "Identifier":
			cur.Identifier = v
		case "URL":
			cur.URL = strings.TrimPrefix(v, "file://")
		case "Executable Path":
			cur.ExecPath = v
		case "Bundle Identifier":
			cur.BundleID = v
		case "Parent Identifier":
			cur.Parent = v
		case "Last Use":
			cur.Used = v
		}
	}
	flush()
	return out
}

func btmHex(v string) uint64 {
	m := btmHexRe.FindStringSubmatch(v)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseUint(m[1][2:], 16, 64)
	return n
}

// label returns the identifier without BTM's "<type>." prefix ("8.com.x.agent" -> "com.x.agent").
func (it btmItem) label() string {
	if i := strings.IndexByte(it.Identifier, '.'); i > 0 {
		if _, err := strconv.Atoi(it.Identifier[:i]); err == nil {
			return it.Identifier[i+1:]
		}
	}
	return it.Identifier
}

func (it btmItem) enabled() bool {
	return it.Disposition&btmEnabled != 0 && it.Disposition&btmAllowed != 0
}

// btmAutoruns turns BTM records into persistence.autoruns rows. rows are the launchd rows
// already collected from the LaunchAgents/LaunchDaemons folders: a legacy BTM job with
// the same label annotates its row (switched off in Login Items means not enabled) instead
// of adding a duplicate. userName maps a UID to an account name.
func btmAutoruns(items []btmItem, rows []platform.Row, userName func(uid int) string) []platform.Row {
	byID := map[string]btmItem{}
	for _, it := range items {
		if _, dup := byID[btmKey(it.UID, it.Identifier)]; !dup {
			byID[btmKey(it.UID, it.Identifier)] = it
		}
	}
	// Launchd rows by label; a label switched off for every user counts as off.
	launchd := map[string][]platform.Row{}
	for _, r := range rows {
		if t, _ := r["type"].(string); t == "launch_agent" || t == "launch_daemon" {
			if n, _ := r["name"].(string); n != "" {
				launchd[n] = append(launchd[n], r)
			}
		}
	}
	legacyOn := map[string]bool{}
	legacySeen := map[string]bool{}
	var out []platform.Row
	added := map[string]bool{}
	for _, it := range items {
		typ := it.Type &^ btmLegacy
		var rowType string
		switch {
		case typ == btmLoginItem:
			rowType = "login_item"
		case typ == btmBackgroundTask:
			rowType = "background_task"
		case typ == btmAgent:
			rowType = "launch_agent"
		case typ == btmDaemon:
			rowType = "launch_daemon"
		default:
			continue // apps, developers, Spotlight and Quick Look plug-ins
		}
		if it.Type&btmLegacy != 0 && len(launchd[it.label()]) > 0 {
			legacySeen[it.label()] = true
			legacyOn[it.label()] = legacyOn[it.label()] || it.enabled()
			continue
		}
		parent := ""
		if p, ok := byID[btmKey(it.UID, it.Parent)]; ok && p.Type&^btmLegacy == btmApp {
			parent = p.URL
		}
		loc := it.URL
		if loc != "" && !strings.HasPrefix(loc, "/") && parent != "" {
			loc = path.Join(parent, loc) // relative to the app that registered it
		}
		if loc == "" {
			loc = parent
		}
		cmd := it.ExecPath
		if cmd == "" {
			cmd = loc
		}
		name := it.Name
		if name == "" {
			name = it.label()
		}
		user := ""
		if it.UID >= 0 {
			user = userName(it.UID)
		}
		key := rowType + "\x00" + user + "\x00" + it.Identifier + "\x00" + loc
		if added[key] {
			continue
		}
		added[key] = true
		r := autorunRow(rowType, loc, name, cmd, user, it.enabled())
		r["source"] = "btm"
		r["identifier"] = it.label()
		setNonEmpty(r, "developer", it.Developer)
		setNonEmpty(r, "team_id", it.TeamID)
		setNonEmpty(r, "bundle_id", it.BundleID)
		if p, ok := byID[btmKey(it.UID, it.Parent)]; ok && p.Type&^btmLegacy == btmApp {
			setNonEmpty(r, "parent", p.label())
		}
		setNonEmpty(r, "last_used", it.Used)
		out = append(out, r)
	}
	for label := range legacySeen {
		for _, r := range launchd[label] {
			r["login_items_allowed"] = legacyOn[label]
			if !legacyOn[label] {
				r["enabled"] = false
			}
		}
	}
	return out
}

func btmKey(uid int, id string) string { return strconv.Itoa(uid) + "\x00" + id }

func setNonEmpty(r platform.Row, k, v string) {
	if v != "" {
		r[k] = v
	}
}
