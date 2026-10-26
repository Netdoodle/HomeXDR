package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
)

// releaseDirs builds a downloads dir with a signed bundled release of version.
type releaseDirs struct {
	t                        *testing.T
	downloads, sigs, archive string
	priv                     ed25519.PrivateKey
	log                      *slog.Logger
}

func newReleaseDirs(t *testing.T) *releaseDirs {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := &releaseDirs{t: t, downloads: t.TempDir(), sigs: t.TempDir(), archive: filepath.Join(t.TempDir(), "releases"),
		priv: priv, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	os.WriteFile(filepath.Join(d.sigs, UpdateKeyFile), []byte(api.FormatUpdateKey(pub)+"\n"), 0o644)
	return d
}

// bundle makes version the bundled, signed release.
func (d *releaseDirs) bundle(version string, commitTime int64) {
	d.t.Helper()
	os.WriteFile(filepath.Join(d.downloads, "homexdr-agent-linux-amd64"), []byte("binary "+version), 0o755)
	if _, err := WriteManifest(d.downloads, version, "c"+version, commitTime); err != nil {
		d.t.Fatal(err)
	}
	m, _ := os.ReadFile(filepath.Join(d.downloads, api.AgentReleaseName))
	os.WriteFile(filepath.Join(d.sigs, SignatureFile(m)), api.SignRelease(d.priv, m), 0o644)
}

func (d *releaseDirs) release(keep int, protect ...string) *Release {
	r := NewRelease(d.downloads, d.sigs, d.log)
	r.SetArchive(d.archive, keep, func() []string { return protect })
	return r
}

func versions(list []ArchivedRelease) string {
	var v []string
	for _, a := range list {
		v = append(v, a.Version)
	}
	return strings.Join(v, ",")
}

func TestReleaseArchive(t *testing.T) {
	d := newReleaseDirs(t)
	for i, v := range []string{"v1", "v2", "v3", "v4"} {
		d.bundle(v, int64(100*(i+1)))
		d.release(10).Archive() // each server version archives its bundled release
	}
	r := d.release(10)
	if got := versions(r.Archive()); got != "v4,v3,v2,v1" {
		t.Fatalf("archive = %s", got)
	}
	if a := r.Archive()[0]; !a.Bundled || a.Path() != "/v1/releases/v4/" || a.ArchivedAt.IsZero() {
		t.Fatalf("newest release %+v", a)
	}
	if p, ok := r.ArchiveFile("v2", "homexdr-agent-linux-amd64"); !ok || !strings.HasSuffix(p, filepath.Join("v2", "homexdr-agent-linux-amd64")) {
		t.Fatalf("ArchiveFile = %q %v", p, ok)
	}
	if b, _ := os.ReadFile(filepath.Join(d.archive, "v2", "homexdr-agent-linux-amd64")); string(b) != "binary v2" {
		t.Fatalf("archived binary %q", b)
	}
	for _, bad := range [][2]string{{"v2", "../v1/agent-release.json"}, {"v9", api.AgentReleaseName}, {"v2", "other-file"}} {
		if _, ok := r.ArchiveFile(bad[0], bad[1]); ok {
			t.Errorf("ArchiveFile(%q, %q) allowed", bad[0], bad[1])
		}
	}

	// A tampered archived release is not offered.
	os.WriteFile(filepath.Join(d.archive, "v2", api.AgentReleaseName), []byte(`{"version":"v2","commit_time":999}`), 0o644)
	if got := versions(d.release(10).Archive()); got != "v4,v3,v1" {
		t.Fatalf("archive after tampering = %s", got)
	}

	// Pruning keeps the newest, the bundled release and protected versions.
	if got := versions(d.release(2, "v1").Archive()); got != "v4,v3,v1" {
		t.Fatalf("pruned archive = %s", got)
	}
	if _, err := os.Stat(filepath.Join(d.archive, "v1")); err != nil {
		t.Fatal("protected release removed")
	}
}

func host(version string, labels ...string) *store.Host {
	if labels == nil {
		labels = []string{}
	}
	return &store.Host{ID: "h-" + version, Hostname: "host-" + version, Kind: store.HostEndpoint, AgentVersion: version, Labels: labels}
}

var testArchive = []ArchivedRelease{
	{Version: "0.0.0-20261020000000.ccc", CommitTime: 300, ArchivedAt: time.Now().Add(-48 * time.Hour)},
	{Version: "0.0.0-20261010000000.bbb", CommitTime: 200, ArchivedAt: time.Now().Add(-30 * 24 * time.Hour)},
	{Version: "0.0.0-20261001000000.aaa", CommitTime: 100, ArchivedAt: time.Now().Add(-60 * 24 * time.Hour)},
}

func TestUpdateStatus(t *testing.T) {
	c := &Core{}
	latest, n1, oldest := testArchive[0].Version, testArchive[1].Version, testArchive[2].Version
	now := time.Now()
	base := DefaultAgentLifecycle()
	cases := []struct {
		name   string
		edit   func(*AgentLifecycle)
		h      *store.Host
		hosts  []*store.Host
		at     time.Time
		state  string
		target string
		offer  bool
	}{
		{"latest", nil, host(oldest), nil, now, UpdStateUpdating, latest, true},
		{"current", nil, host(latest), nil, now, UpdStateCurrent, latest, false},
		{"n-1", func(l *AgentLifecycle) { l.Updates.Default = UpdateRule{Mode: UpdateN1} }, host(oldest), nil, now, UpdStateUpdating, n1, true},
		{"no downgrade", func(l *AgentLifecycle) { l.Updates.Default = UpdateRule{Mode: UpdateN1} }, host(latest), nil, now, UpdStateAhead, n1, false},
		{"pinned", func(l *AgentLifecycle) { l.Updates.Default = UpdateRule{Mode: UpdatePinned, Version: n1} }, host(oldest), nil, now, UpdStateUpdating, n1, true},
		{"pinned missing", func(l *AgentLifecycle) { l.Updates.Default = UpdateRule{Mode: UpdatePinned, Version: "gone"} }, host(oldest), nil, now, UpdStateNone, "", false},
		{"off", func(l *AgentLifecycle) { l.Updates.Default = UpdateRule{Mode: UpdateOff} }, host(oldest), nil, now, UpdStateOff, "", false},
		{"label rule wins", func(l *AgentLifecycle) {
			l.Updates.Labels = []LabelRule{{Label: "servers", Rule: UpdateRule{Mode: UpdateOff}}}
		}, host(oldest, "Servers"), nil, now, UpdStateOff, "", false},
		{"unknown version from string", nil, &store.Host{Kind: store.HostEndpoint, AgentVersion: "0.0.0-20261101000000.zzz"}, nil, now, UpdStateAhead, latest, false},
		{"failed", nil, func() *store.Host { h := host(oldest); h.UpdateError = latest + ": checksum mismatch"; return h }(), nil, now, UpdStateFailed, latest, true},
	}
	for _, tc := range cases {
		l := base
		l.Updates.Labels = []LabelRule{}
		if tc.edit != nil {
			tc.edit(&l)
		}
		hu := c.UpdateStatus(l, tc.h, testArchive, tc.hosts, tc.at)
		if hu.State != tc.state || hu.Target != tc.target || (hu.offer != nil) != tc.offer {
			t.Errorf("%s: state %s target %q offer %v (%s)", tc.name, hu.State, hu.Target, hu.offer != nil, hu.Reason)
		}
		if hu.offer != nil && hu.offer.Path != api.PathReleases+hu.Target+"/" {
			t.Errorf("%s: offer path %q", tc.name, hu.offer.Path)
		}
	}
}

func TestUpdateWindowAndStaging(t *testing.T) {
	c := &Core{}
	l := DefaultAgentLifecycle()
	l.Updates.Window = MaintenanceWindow{Enabled: true, Start: "23:00", End: "02:00", Timezone: "America/Chicago"}
	chicago, _ := time.LoadLocation("America/Chicago")
	noon := time.Date(2026, 10, 26, 12, 0, 0, 0, chicago)
	night := time.Date(2026, 10, 27, 1, 30, 0, 0, chicago)
	old := host(testArchive[2].Version)
	if hu := c.UpdateStatus(l, old, testArchive, nil, noon); hu.State != UpdStatePending || !strings.Contains(hu.Reason, "maintenance window") {
		t.Fatalf("outside window: %s %s", hu.State, hu.Reason)
	}
	if hu := c.UpdateStatus(l, old, testArchive, nil, night); hu.offer == nil {
		t.Fatalf("inside a window that wraps midnight: %s %s", hu.State, hu.Reason)
	}
	now := time.Now()
	nowHost := host(testArchive[2].Version)
	nowHost.UpdateNowAt = &now
	if hu := c.UpdateStatus(l, nowHost, testArchive, nil, noon); hu.offer == nil {
		t.Fatal("update now did not bypass the window")
	}

	// Staged: the newest release is 48h old.
	l.Updates.Window.Enabled = false
	l.Updates.Staged = StagedRollout{Enabled: true, CanaryLabel: "canary", DelayHours: 72}
	canary := host(testArchive[2].Version, "canary")
	if hu := c.UpdateStatus(l, canary, testArchive, nil, now); hu.offer == nil {
		t.Fatal("canary held back")
	}
	if hu := c.UpdateStatus(l, old, testArchive, []*store.Host{canary}, now); hu.offer != nil || !strings.Contains(hu.Reason, "canary agents first") {
		t.Fatalf("non-canary within the delay: %s %s", hu.State, hu.Reason)
	}
	l.Updates.Staged.DelayHours = 24
	if hu := c.UpdateStatus(l, old, testArchive, []*store.Host{canary}, now); hu.offer != nil || !strings.Contains(hu.Reason, "waiting for") {
		t.Fatalf("no canary on the release yet: %s %s", hu.State, hu.Reason)
	}
	failed := host(testArchive[2].Version, "canary")
	failed.UpdateError = testArchive[0].Version + ": did not start"
	if hu := c.UpdateStatus(l, old, testArchive, []*store.Host{host(testArchive[0].Version, "canary"), failed}, now); hu.offer != nil || !strings.Contains(hu.Reason, "failed") {
		t.Fatalf("a canary failed: %s %s", hu.State, hu.Reason)
	}
	if hu := c.UpdateStatus(l, old, testArchive, []*store.Host{host(testArchive[0].Version, "canary")}, now); hu.offer == nil {
		t.Fatalf("healthy canaries: %s %s", hu.State, hu.Reason)
	}
	if hu := c.UpdateStatus(l, old, testArchive, nil, now); hu.offer == nil {
		t.Fatalf("no canary agents at all: delay only: %s %s", hu.State, hu.Reason)
	}
}

func TestAgentLifecycleValidate(t *testing.T) {
	for i, bad := range []func(*AgentLifecycle){
		func(l *AgentLifecycle) { l.DecommissionAfterDays = -1 },
		func(l *AgentLifecycle) { l.Updates.Default.Mode = "sometimes" },
		func(l *AgentLifecycle) { l.Updates.Default = UpdateRule{Mode: UpdatePinned} },
		func(l *AgentLifecycle) {
			l.Updates.Labels = []LabelRule{{Label: "", Rule: UpdateRule{Mode: UpdateOff}}}
		},
		func(l *AgentLifecycle) {
			l.Updates.Labels = []LabelRule{{Label: "a", Rule: UpdateRule{Mode: UpdateOff}}, {Label: "A", Rule: UpdateRule{Mode: UpdateLatest}}}
		},
		func(l *AgentLifecycle) {
			l.Updates.Window = MaintenanceWindow{Enabled: true, Start: "25:00", End: "02:00"}
		},
		func(l *AgentLifecycle) { l.Updates.Window.Timezone = "Mars/Olympus" },
	} {
		l := DefaultAgentLifecycle()
		bad(&l)
		if err := l.Validate(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	l := DefaultAgentLifecycle()
	l.Updates.Default = UpdateRule{Mode: " Latest ", Version: "ignored"}
	if err := l.Validate(); err != nil || l.Updates.Default.Mode != UpdateLatest || l.Updates.Default.Version != "" {
		t.Fatalf("normalize: %v %+v", err, l.Updates.Default)
	}
}
