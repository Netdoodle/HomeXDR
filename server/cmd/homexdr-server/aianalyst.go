package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/triage"
)

// aiAnalyst turns the AI analyst on or off from the command line (for example when
// provider charges run up), without signing in to the console:
//
//	homexdr-server ai-analyst off|on|status
//
// Only the "enabled" switch changes; the provider, model, limits and stored API keys
// stay as they are, and no key is ever printed. The running server reads the setting on
// every investigation, so the change applies at once.
func aiAnalyst(args []string) int {
	if len(args) != 1 || (args[0] != "on" && args[0] != "off" && args[0] != "status") {
		fmt.Fprintln(os.Stderr, "usage: homexdr-server ai-analyst on|off|status")
		return 2
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer st.Close()
	ctx := context.Background()
	// A generic map keeps every stored field (including keys) exactly as it is.
	raw := map[string]any{}
	if err := st.GetKV(ctx, triage.SettingsKey, &raw); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		def := triage.DefaultSettings()
		raw = map[string]any{
			"enabled": def.Enabled, "provider": def.Provider, "model": def.Model, "min_severity": def.MinSeverity,
			"daily_limit": def.DailyLimit, "max_tool_calls": def.MaxToolCalls, "engine": def.Engine,
		}
	}
	was, _ := raw["enabled"].(bool)
	fmt.Printf("AI analyst: %s (engine %v, provider %v, daily limit %v)\n", onOff(was), raw["engine"], raw["provider"], raw["daily_limit"])
	if args[0] == "status" {
		return 0
	}
	want := args[0] == "on"
	if want == was {
		fmt.Println("nothing to change")
		return 0
	}
	raw["enabled"] = want
	if err := st.SetKV(ctx, triage.SettingsKey, raw); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = st.Audit(ctx, "cli", "settings.ai", "", "ai-analyst "+args[0])
	fmt.Printf("AI analyst turned %s\n", onOff(want))
	return 0
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
