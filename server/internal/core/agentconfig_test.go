package core

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
)

func TestAgentConfigDecoyDefaults(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := &Core{State: st}

	def := c.AgentConfig(ctx)
	if !def.Decoys.Enabled || def.Decoys.CheckIntervalSec != 60 || def.Version != 5 || !def.Sysmon.Enabled || !reflect.DeepEqual(def.Decoys.Files, api.DefaultDecoyFiles()) {
		t.Fatalf("default: %+v version %d", def.Decoys, def.Version)
	}

	// A config saved before decoy files existed: decoys on, version raised so agents on
	// version 7 receive it.
	if err := st.SetKV(ctx, agentConfigKey, map[string]any{"version": 7, "heartbeat_interval_sec": 30}); err != nil {
		t.Fatal(err)
	}
	old := c.AgentConfig(ctx)
	if !old.Decoys.Enabled || !old.Sysmon.Enabled || old.Version != 8 || old.HeartbeatIntervalSec != 30 || len(old.Decoys.Files) != len(api.DefaultDecoyFiles()) {
		t.Fatalf("old config: %+v version %d", old.Decoys, old.Version)
	}

	// Saving keeps the version rising and stores the choice, including off.
	old.Decoys = api.DecoyConfig{Enabled: false, CheckIntervalSec: 5, Files: []api.DecoyFile{
		{OS: api.DecoyOSLinux, Path: " /srv/keys.txt "},
		{OS: api.DecoyOSWindows, Path: `C:\Users\Public\x.csv`, Hidden: true},
	}}
	saved, err := c.SetAgentConfig(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Version != 9 || saved.Decoys.Enabled || saved.Decoys.CheckIntervalSec != api.DecoyMinIntervalSec || len(saved.Decoys.Files) != 2 || saved.Decoys.Files[0].Path != "/srv/keys.txt" {
		t.Fatalf("saved: %+v version %d", saved.Decoys, saved.Version)
	}
	if got := c.AgentConfig(ctx); got.Version != 9 || got.Decoys.Enabled || !reflect.DeepEqual(got.Decoys.Files, saved.Decoys.Files) {
		t.Fatalf("reloaded: %+v version %d", got.Decoys, got.Version)
	}

	// An empty list is kept as empty (not replaced by the defaults).
	empty := saved
	empty.Decoys.Files = nil
	if _, err := c.SetAgentConfig(ctx, empty); err != nil {
		t.Fatal(err)
	}
	if got := c.AgentConfig(ctx); got.Version != 10 || got.Decoys.Files == nil || len(got.Decoys.Files) != 0 {
		t.Fatalf("empty list: %+v version %d", got.Decoys.Files, got.Version)
	}

	for _, bad := range []api.DecoyFile{
		{OS: api.DecoyOSLinux, Path: "relative.txt"},
		{OS: api.DecoyOSLinux, Path: "/srv/*.txt"},
		{OS: api.DecoyOSLinux, Path: "/srv/dir/"},
		{OS: api.DecoyOSWindows, Path: `C:relative`},
		{OS: api.DecoyOSLinux, Path: "/"},
		{OS: api.DecoyOSLinux, Path: "{home}/../etc/x"},
		{OS: api.DecoyOSWindows, Path: "{home}/x.txt"},
		{OS: "beos", Path: "/x.txt"},
	} {
		cfg := saved
		cfg.Decoys.Files = []api.DecoyFile{bad}
		var ve *ValidationError
		if _, err := c.SetAgentConfig(ctx, cfg); !errors.As(err, &ve) {
			t.Errorf("%+v: err %v", bad, err)
		}
	}
}

// A config saved with decoys but before decoy paths were configurable: it gets the
// default paths (no Desktop decoys) plus its old extra paths, and a higher version.
func TestAgentConfigOldExtraPaths(t *testing.T) {
	raw := []byte(`{"version":12,"heartbeat_interval_sec":30,"decoys":{"enabled":true,"check_interval_sec":120,"extra":["/srv/share/keys.txt","D:\\Shares\\pay.csv"]}}`)
	cfg := ParseAgentConfig(raw)
	if cfg.Version != 13 || cfg.Decoys.CheckIntervalSec != 120 || !cfg.Decoys.Enabled {
		t.Fatalf("old config: %+v version %d", cfg.Decoys, cfg.Version)
	}
	// The defaults, then the converted extras in their order.
	want := append(api.DefaultDecoyFiles(),
		api.DecoyFile{OS: api.DecoyOSLinux, Path: "/srv/share/keys.txt"},
		api.DecoyFile{OS: api.DecoyOSDarwin, Path: "/srv/share/keys.txt"},
		api.DecoyFile{OS: api.DecoyOSWindows, Path: `D:\Shares\pay.csv`},
	)
	if !reflect.DeepEqual(cfg.Decoys.Files, want) {
		t.Fatalf("files:\n%+v\nwant\n%+v", cfg.Decoys.Files, want)
	}
	// With a files list the version is served as stored.
	cur := ParseAgentConfig([]byte(`{"version":12,"decoys":{"enabled":true,"check_interval_sec":60,"files":[]},"sysmon":{"enabled":true}}`))
	if cur.Version != 12 || len(cur.Decoys.Files) != 0 {
		t.Fatalf("current config: %+v version %d", cur.Decoys, cur.Version)
	}
}

// A config saved before Sysmon management existed gets it on, with a higher version; a
// saved choice (on or off) is served as stored.
func TestAgentConfigSysmonDefault(t *testing.T) {
	cases := []struct {
		raw     string
		on      bool
		version int64
	}{
		{`{"version":20,"decoys":{"enabled":true,"check_interval_sec":60,"files":[]}}`, true, 21},
		{`{"version":20,"decoys":{"enabled":true,"check_interval_sec":60,"files":[]},"sysmon":null}`, true, 21},
		{`{"version":20,"decoys":{"enabled":true,"check_interval_sec":60,"files":[]},"sysmon":{"enabled":false}}`, false, 20},
		{`{"version":20,"decoys":{"enabled":true,"check_interval_sec":60,"files":[]},"sysmon":{"enabled":true}}`, true, 20},
		// Neither decoys nor sysmon: both defaults, one version step.
		{`{"version":20}`, true, 21},
	}
	for _, c := range cases {
		cfg := ParseAgentConfig([]byte(c.raw))
		if cfg.Sysmon.Enabled != c.on || cfg.Version != c.version {
			t.Errorf("%s: sysmon %v version %d, want %v %d", c.raw, cfg.Sysmon.Enabled, cfg.Version, c.on, c.version)
		}
	}
}
