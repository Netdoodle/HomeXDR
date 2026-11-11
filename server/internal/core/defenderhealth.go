package core

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Microsoft Defender health, from the Defender log the Windows eventlog sensor forwards:
// the periodic health report (1151) and real-time protection being turned off (5001).
const (
	RuleDefenderOff   = "defender:protection-off"
	RuleDefenderStale = "defender:signatures-stale"
	// defenderStaleDays: signatures older than this raise an alert.
	defenderStaleDays = 3
)

func (c *Core) observeDefender(ctx context.Context, host *store.Host, evs []*event.Event) {
	if host == nil || host.Kind != store.HostEndpoint {
		return
	}
	for _, e := range evs {
		if e.Event.Module != event.ModuleEventLog || !strings.EqualFold(e.Event.Provider, "Microsoft-Windows-Windows Defender") {
			continue
		}
		str := func(k string) string { s, _ := e.Data[k].(string); return strings.TrimSpace(s) }
		switch e.Event.Code {
		case "5001":
			c.defenderFinding(ctx, host, RuleDefenderOff, store.SevHigh,
				"Microsoft Defender real-time protection was turned off",
				"real-time protection was turned off (event 5001)")
		case "1151":
			for _, k := range []string{"RTP state", "BM state"} {
				if v := str(k); v != "" && !strings.EqualFold(v, "Enabled") {
					what := map[string]string{"RTP state": "real-time protection", "BM state": "behavior monitoring"}[k]
					c.defenderFinding(ctx, host, RuleDefenderOff, store.SevHigh,
						"Microsoft Defender "+what+" is off",
						fmt.Sprintf("Defender's health report says %s is %s", what, strings.ToLower(v)))
				}
			}
			// 4294967295 means "never".
			if age, err := strconv.ParseUint(str("Last AV security intelligence age"), 10, 32); err == nil && age > defenderStaleDays && age < 4294967295 {
				c.defenderFinding(ctx, host, RuleDefenderStale, store.SevMedium,
					fmt.Sprintf("Microsoft Defender signatures are %d days old", age),
					fmt.Sprintf("Defender's virus signatures (%s) were last updated %d days ago", str("AV security intelligence version"), age))
			}
		}
	}
}

func (c *Core) defenderFinding(ctx context.Context, host *store.Host, rule, sev, title, msg string) {
	f := Finding{
		RuleID: rule, Title: title, Severity: sev, Tags: []string{"homexdr", "defender"},
		Description: "HomeXDR watches Microsoft Defender's own health reports on Windows hosts. " +
			"Turn protection back on or update signatures in Windows Security, or use the Microsoft Defender card on the host page " +
			"(Status, Update signatures). Repeats fold into one open alert per host.",
		Entity: host.ID + "|" + rule, HostID: host.ID, Hostname: host.Hostname, Dataset: "homexdr.defender",
		Message: host.Hostname + ": " + msg,
	}
	if err := c.RaiseFinding(ctx, f); err != nil {
		c.Log.Warn("defender health finding", "err", err)
	}
}
