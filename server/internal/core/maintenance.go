package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Maintenance tuning: name the SSH keys used for maintenance and quiet the alerts their
// sessions raise, and quiet the alerts container updates raise.
//
// The agents label each process with the SSH session it descends from (labels.ssh_session,
// labels.ssh_key) and with the maintenance tooling it descends from (labels.maintenance:
// docker-update, appdata-backup). The server fills in the key when the agent could not,
// names it (labels.ssh_key_name), and marks the first minutes of each new container
// (labels.maintenance: container-start).
//
// Turning maintenance on for a key or a source creates an ordinary suppression on that
// label, managed from here. It shows on the Suppressions page with its hit count, and
// must-alert rules and critical alerts still alert.

const maintenanceSettingsKey = "maintenance_settings"

// Maintenance sources other than SSH keys.
const (
	MaintDockerUpdate   = "docker-update"
	MaintAppdataBackup  = "appdata-backup"
	MaintContainerStart = "container-start"
)

var maintenanceSources = []struct{ ID, Title, Help string }{
	{MaintDockerUpdate, "Docker container updates",
		"Commands started by Unraid's Docker manager or the CA Auto Update plugin while they update, create or start containers."},
	{MaintAppdataBackup, "Appdata backup",
		"Commands started by the appdata backup plugin, which stops every container, backs it up and starts it again."},
	{MaintContainerStart, "Container start-up",
		"Everything a container runs in its first minutes after HomeXDR first sees it: a new or updated container's init scripts."},
}

// SSHKeyTag names an SSH key by its fingerprint.
type SSHKeyTag struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	// Maintenance quiets the alerts raised by commands from this key's sessions.
	Maintenance   bool       `json:"maintenance"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	SuppressionID string     `json:"suppression_id,omitempty"`
}

// MaintenanceSource is one of the container maintenance sources.
type MaintenanceSource struct {
	ID            string     `json:"id"`
	Maintenance   bool       `json:"maintenance"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	SuppressionID string     `json:"suppression_id,omitempty"`
}

// MaintenanceSettings is the stored configuration.
type MaintenanceSettings struct {
	SSHKeys []SSHKeyTag         `json:"ssh_keys"`
	Sources []MaintenanceSource `json:"sources"`
	// ContainerStartMinutes is how long after a container is first seen its processes
	// count as start-up.
	ContainerStartMinutes int `json:"container_start_minutes"`
}

const defaultContainerStartMinutes = 5

// maintTracker holds the in-memory state of maintenance labelling.
type maintTracker struct {
	mu       sync.Mutex
	started  time.Time
	set      MaintenanceSettings
	names    map[string]string               // fingerprint → name
	sessions map[string]map[int64]sshSession // host ID → login PID → session
	conts    map[string]containerSeen        // host ID + container ID → first seen
}

type sshSession struct {
	key string
	at  time.Time
}

type containerSeen struct {
	first time.Time
	fresh bool // first seen while HomeXDR was running long enough to know it was new
}

func newMaintTracker() *maintTracker {
	return &maintTracker{
		started: time.Now(), names: map[string]string{},
		sessions: map[string]map[int64]sshSession{}, conts: map[string]containerSeen{},
	}
}

func (t *maintTracker) apply(s MaintenanceSettings) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.set = s
	t.names = map[string]string{}
	for _, k := range s.SSHKeys {
		if k.Name != "" {
			t.names[k.Fingerprint] = k.Name
		}
	}
}

func (t *maintTracker) window() time.Duration {
	m := t.set.ContainerStartMinutes
	if m <= 0 {
		m = defaultContainerStartMinutes
	}
	return time.Duration(m) * time.Minute
}

// label fills in maintenance labels on an event as it is ingested.
func (t *maintTracker) label(e *event.Event, hostID string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// A login: remember which key the session used.
	if e.Event.Action == "ssh_login" && e.Event.Outcome == event.OutcomeSuccess && e.Process != nil && e.Process.PID > 0 {
		hs := t.sessions[hostID]
		if hs == nil {
			hs = map[int64]sshSession{}
			t.sessions[hostID] = hs
		}
		if len(hs) > 4096 {
			for pid, s := range hs {
				if now.Sub(s.at) > 24*time.Hour {
					delete(hs, pid)
				}
			}
			if len(hs) > 4096 {
				hs = map[int64]sshSession{}
				t.sessions[hostID] = hs
			}
		}
		hs[e.Process.PID] = sshSession{key: e.Labels["ssh_key"], at: now}
	}
	if s := e.Labels["ssh_session"]; s != "" && e.Labels["ssh_key"] == "" {
		if pid, err := strconv.ParseInt(s, 10, 64); err == nil {
			if ss, ok := t.sessions[hostID][pid]; ok && ss.key != "" {
				e.Labels["ssh_key"] = ss.key
			}
		}
	}
	if k := e.Labels["ssh_key"]; k != "" {
		if n := t.names[k]; n != "" {
			e.Labels["ssh_key_name"] = n
		}
	}
	// Container start-up.
	if e.Container != nil && e.Container.ID != "" {
		key := hostID + "/" + e.Container.ID
		c, ok := t.conts[key]
		if !ok {
			c = containerSeen{first: now, fresh: now.Sub(t.started) > t.window()}
			if len(t.conts) > 20000 {
				for k, v := range t.conts {
					if now.Sub(v.first) > 7*24*time.Hour {
						delete(t.conts, k)
					}
				}
			}
			t.conts[key] = c
		}
		if c.fresh && now.Sub(c.first) <= t.window() && e.Labels["maintenance"] == "" {
			if e.Labels == nil {
				e.Labels = map[string]string{}
			}
			e.Labels["maintenance"] = MaintContainerStart
		}
	}
}

// LoadMaintenance reads the stored settings into the tracker.
func (c *Core) LoadMaintenance(ctx context.Context) error {
	s, err := c.maintenanceSettings(ctx)
	if err != nil {
		return err
	}
	c.Maint.apply(s)
	return nil
}

func (c *Core) maintenanceSettings(ctx context.Context) (MaintenanceSettings, error) {
	var s MaintenanceSettings
	if err := c.State.GetKV(ctx, maintenanceSettingsKey, &s); err != nil && !errors.Is(err, store.ErrNotFound) {
		return s, err
	}
	if s.ContainerStartMinutes <= 0 {
		s.ContainerStartMinutes = defaultContainerStartMinutes
	}
	return s, nil
}

// SSHKeySeen is an SSH key that logged in to a monitored host, with its tag.
type SSHKeySeen struct {
	SSHKeyTag
	Logins    int64      `json:"logins"`
	LastLogin *time.Time `json:"last_login,omitempty"`
	Users     []string   `json:"users,omitempty"`
	Hosts     []string   `json:"hosts,omitempty"`
	Sources   []string   `json:"sources,omitempty"`
	// Suppressed counts the alerts its maintenance suppression closed.
	Suppressed int64 `json:"suppressed"`
}

// MaintenanceSourceView is a container maintenance source as the console shows it.
type MaintenanceSourceView struct {
	MaintenanceSource
	Title      string `json:"title"`
	Help       string `json:"help"`
	Suppressed int64  `json:"suppressed"`
}

// MaintenanceView is the maintenance page's data.
type MaintenanceView struct {
	SSHKeys               []SSHKeySeen            `json:"ssh_keys"`
	Sources               []MaintenanceSourceView `json:"sources"`
	ContainerStartMinutes int                     `json:"container_start_minutes"`
	Days                  int                     `json:"days"`
}

// MaintenanceView lists the SSH keys seen in the last days and the maintenance sources.
func (c *Core) MaintenanceView(ctx context.Context, days int) (*MaintenanceView, error) {
	s, err := c.maintenanceSettings(ctx)
	if err != nil {
		return nil, err
	}
	s = c.syncMaintenance(ctx, s)
	sups := map[string]*store.Suppression{}
	if list, err := c.State.ListSuppressions(ctx); err == nil {
		for _, sp := range list {
			sups[sp.ID] = sp
		}
	}
	v := &MaintenanceView{ContainerStartMinutes: s.ContainerStartMinutes, Days: days, SSHKeys: []SSHKeySeen{}}
	byFP := map[string]*SSHKeySeen{}
	for _, k := range s.SSHKeys {
		kv := &SSHKeySeen{SSHKeyTag: k}
		if sp := sups[k.SuppressionID]; sp != nil {
			kv.Suppressed = sp.HitCount
		}
		byFP[k.Fingerprint] = kv
	}
	res, err := c.Events.Search(ctx, events.SearchQuery{
		From: time.Now().Add(-time.Duration(days) * 24 * time.Hour),
		Query: `event.action:ssh_login event.outcome:success | stats count, max(@timestamp) as last, values(user.name) as users, ` +
			`values(host.name) as hosts, values(source.ip) as sources by labels.ssh_key`,
	})
	if err == nil {
		for _, row := range res.Rows {
			if len(row) < 6 {
				continue
			}
			fp := fmt.Sprint(row[0])
			if fp == "" || fp == "<nil>" {
				continue
			}
			kv := byFP[fp]
			if kv == nil {
				kv = &SSHKeySeen{SSHKeyTag: SSHKeyTag{Fingerprint: fp}}
				byFP[fp] = kv
			}
			kv.Logins = toInt64(row[1])
			if t, ok := toTime(row[2]); ok {
				kv.LastLogin = &t
			}
			kv.Users, kv.Hosts, kv.Sources = toStrings(row[3]), toStrings(row[4]), toStrings(row[5])
		}
	}
	for _, kv := range byFP {
		v.SSHKeys = append(v.SSHKeys, *kv)
	}
	sort.Slice(v.SSHKeys, func(i, j int) bool {
		a, b := v.SSHKeys[i], v.SSHKeys[j]
		if (a.Name != "") != (b.Name != "") {
			return a.Name != ""
		}
		return a.Logins > b.Logins
	})
	have := map[string]MaintenanceSource{}
	for _, src := range s.Sources {
		have[src.ID] = src
	}
	for _, d := range maintenanceSources {
		src := have[d.ID]
		src.ID = d.ID
		sv := MaintenanceSourceView{MaintenanceSource: src, Title: d.Title, Help: d.Help}
		if sp := sups[src.SuppressionID]; sp != nil {
			sv.Suppressed = sp.HitCount
		}
		v.Sources = append(v.Sources, sv)
	}
	return v, nil
}

// syncMaintenance turns maintenance off where its suppression was deleted or switched
// off on the Suppressions page, so this page never claims more than is in force.
func (c *Core) syncMaintenance(ctx context.Context, s MaintenanceSettings) MaintenanceSettings {
	live := func(id string) bool {
		if id == "" {
			return false
		}
		sp, err := c.State.GetSuppression(ctx, id)
		return err == nil && sp.Active(time.Now())
	}
	for i := range s.SSHKeys {
		if s.SSHKeys[i].Maintenance && !live(s.SSHKeys[i].SuppressionID) {
			s.SSHKeys[i].Maintenance, s.SSHKeys[i].SuppressionID = false, ""
		}
	}
	for i := range s.Sources {
		if s.Sources[i].Maintenance && !live(s.Sources[i].SuppressionID) {
			s.Sources[i].Maintenance, s.Sources[i].SuppressionID = false, ""
		}
	}
	return s
}

// MaintenanceInput is a settings update from the console.
type MaintenanceInput struct {
	SSHKeys               []SSHKeyTag         `json:"ssh_keys"`
	Sources               []MaintenanceSource `json:"sources"`
	ContainerStartMinutes int                 `json:"container_start_minutes"`
}

var fingerprintChars = func(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '='
}

func validFingerprint(fp string) bool {
	rest, ok := strings.CutPrefix(fp, "SHA256:")
	if !ok || len(rest) < 20 || len(rest) > 64 {
		return false
	}
	for _, r := range rest {
		if !fingerprintChars(r) {
			return false
		}
	}
	return true
}

// SaveMaintenance stores the tags and creates or removes the maintenance suppressions.
func (c *Core) SaveMaintenance(ctx context.Context, in MaintenanceInput, user string) (*MaintenanceView, error) {
	cur, err := c.maintenanceSettings(ctx)
	if err != nil {
		return nil, err
	}
	cur = c.syncMaintenance(ctx, cur)
	if in.ContainerStartMinutes == 0 {
		in.ContainerStartMinutes = defaultContainerStartMinutes
	}
	if in.ContainerStartMinutes < 1 || in.ContainerStartMinutes > 120 {
		return nil, invalid("container start-up lasts 1 to 120 minutes")
	}
	now := time.Now().UTC()
	oldKey := map[string]SSHKeyTag{}
	for _, k := range cur.SSHKeys {
		oldKey[k.Fingerprint] = k
	}
	next := MaintenanceSettings{ContainerStartMinutes: in.ContainerStartMinutes, SSHKeys: []SSHKeyTag{}, Sources: []MaintenanceSource{}}
	seen := map[string]bool{}
	for _, k := range in.SSHKeys {
		k.Fingerprint, k.Name = strings.TrimSpace(k.Fingerprint), strings.TrimSpace(k.Name)
		if !validFingerprint(k.Fingerprint) {
			return nil, invalid("%q is not an SSH key fingerprint (SHA256:...)", k.Fingerprint)
		}
		if seen[k.Fingerprint] {
			continue
		}
		seen[k.Fingerprint] = true
		if len(k.Name) > 80 {
			return nil, invalid("a key name is at most 80 characters")
		}
		if k.Maintenance && k.Name == "" {
			return nil, invalid("name the key before using it for maintenance")
		}
		if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
			return nil, invalid("the maintenance end for %s is in the past", k.Name)
		}
		old := oldKey[k.Fingerprint]
		label := fmt.Sprintf("SSH key %q (%s)", k.Name, k.Fingerprint)
		id, err := c.reconcileMaintenance(ctx, old.Maintenance, old.SuppressionID, old.ExpiresAt, old.Name != k.Name,
			k.Maintenance, k.ExpiresAt, "labels.ssh_key", k.Fingerprint, label, user)
		if err != nil {
			return nil, err
		}
		k.SuppressionID = id
		if !k.Maintenance {
			k.ExpiresAt = nil
		}
		if k.Name == "" && !k.Maintenance {
			continue // nothing left to remember
		}
		next.SSHKeys = append(next.SSHKeys, k)
	}
	for fp, old := range oldKey { // keys left out of the input lose their maintenance
		if !seen[fp] && old.SuppressionID != "" {
			_ = c.DeleteSuppression(ctx, old.SuppressionID, user)
		}
	}
	oldSrc := map[string]MaintenanceSource{}
	for _, s := range cur.Sources {
		oldSrc[s.ID] = s
	}
	for _, d := range maintenanceSources {
		var want MaintenanceSource
		for _, s := range in.Sources {
			if s.ID == d.ID {
				want = s
			}
		}
		want.ID = d.ID
		if want.ExpiresAt != nil && !want.ExpiresAt.After(now) {
			return nil, invalid("the maintenance end for %s is in the past", d.Title)
		}
		old := oldSrc[d.ID]
		id, err := c.reconcileMaintenance(ctx, old.Maintenance, old.SuppressionID, old.ExpiresAt, false,
			want.Maintenance, want.ExpiresAt, "labels.maintenance", d.ID, d.Title, user)
		if err != nil {
			return nil, err
		}
		want.SuppressionID = id
		if !want.Maintenance {
			want.ExpiresAt = nil
		}
		next.Sources = append(next.Sources, want)
	}
	if err := c.State.SetKV(ctx, maintenanceSettingsKey, next); err != nil {
		return nil, err
	}
	c.Maint.apply(next)
	c.Audit(ctx, user, "settings.maintenance", "", describeMaintenance(next))
	return c.MaintenanceView(ctx, 30)
}

// reconcileMaintenance makes the suppression for one key or source match what is wanted,
// and returns its ID ("" when off). A changed end or name replaces it.
func (c *Core) reconcileMaintenance(ctx context.Context, had bool, id string, hadEnd *time.Time, renamed bool,
	want bool, end *time.Time, field, value, label, user string) (string, error) {
	sameEnd := (hadEnd == nil && end == nil) || (hadEnd != nil && end != nil && hadEnd.Equal(*end))
	if had && want && sameEnd && !renamed {
		return id, nil
	}
	if had && id != "" {
		if err := c.DeleteSuppression(ctx, id, user); err != nil && !errors.Is(err, store.ErrNotFound) {
			return "", err
		}
	}
	if !want {
		return "", nil
	}
	spec := SuppressionSpec{
		Conditions:   []store.SuppressionCondition{{Field: field, Op: "equals", Value: value}},
		Reason:       "Maintenance: " + label + ". Managed on Settings → Maintenance.",
		NeverExpires: end == nil,
		ExpiresAt:    end,
	}
	res, err := c.CreateSuppression(ctx, spec, user)
	if err != nil {
		return "", err
	}
	return res.Suppression.ID, nil
}

func describeMaintenance(s MaintenanceSettings) string {
	var on []string
	for _, k := range s.SSHKeys {
		if k.Maintenance {
			on = append(on, "key "+k.Name)
		}
	}
	for _, src := range s.Sources {
		if src.Maintenance {
			on = append(on, src.ID)
		}
	}
	if len(on) == 0 {
		return "no maintenance suppressions"
	}
	return "maintenance: " + strings.Join(on, ", ")
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case uint64:
		return int64(n)
	case float64:
		return int64(n)
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	i, _ := strconv.ParseInt(fmt.Sprint(v), 10, 64)
	return i
}

func toTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t.UTC(), !t.IsZero()
	case string:
		for _, f := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
			if p, err := time.Parse(f, t); err == nil {
				return p.UTC(), true
			}
		}
	}
	return time.Time{}, false
}

func toStrings(v any) []string {
	var out []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" && s != "<nil>" && len(out) < 20 {
			out = append(out, s)
		}
	}
	switch x := v.(type) {
	case []string:
		for _, s := range x {
			add(s)
		}
	case []any:
		for _, s := range x {
			add(fmt.Sprint(s))
		}
	case string:
		for _, s := range strings.Split(x, ",") {
			add(s)
		}
	case nil:
	default:
		add(fmt.Sprint(x))
	}
	return out
}
