package core

import (
	"context"
	"errors"
	"path/filepath"
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
	if !def.Decoys.Enabled || def.Decoys.CheckIntervalSec != 60 || def.Version != 3 {
		t.Fatalf("default: %+v version %d", def.Decoys, def.Version)
	}

	// A config saved before decoy files existed: decoys on, version raised so agents on
	// version 7 receive it.
	if err := st.SetKV(ctx, agentConfigKey, map[string]any{"version": 7, "heartbeat_interval_sec": 30}); err != nil {
		t.Fatal(err)
	}
	old := c.AgentConfig(ctx)
	if !old.Decoys.Enabled || old.Version != 8 || old.HeartbeatIntervalSec != 30 {
		t.Fatalf("old config: %+v version %d", old.Decoys, old.Version)
	}

	// Saving keeps the version rising and stores the choice, including off.
	old.Decoys = api.DecoyConfig{Enabled: false, CheckIntervalSec: 5, Extra: []string{" /srv/keys.txt ", `C:\Users\Public\x.csv`, "/srv/keys.txt", ""}}
	saved, err := c.SetAgentConfig(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Version != 9 || saved.Decoys.Enabled || saved.Decoys.CheckIntervalSec != api.DecoyMinIntervalSec || len(saved.Decoys.Extra) != 2 {
		t.Fatalf("saved: %+v version %d", saved.Decoys, saved.Version)
	}
	if got := c.AgentConfig(ctx); got.Version != 9 || got.Decoys.Enabled {
		t.Fatalf("reloaded: %+v version %d", got.Decoys, got.Version)
	}

	for _, bad := range []string{"relative.txt", "/srv/*.txt", "/srv/dir/", `C:relative`, "/"} {
		cfg := saved
		cfg.Decoys.Extra = []string{bad}
		var ve *ValidationError
		if _, err := c.SetAgentConfig(ctx, cfg); !errors.As(err, &ve) {
			t.Errorf("%q: err %v", bad, err)
		}
	}
}
