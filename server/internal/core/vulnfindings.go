package core

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// RuleVulnKEV is the alert older versions raised for a confirmed known-exploited vulnerability.
// Vulnerabilities now live on the Vulnerabilities page and raise no alerts; open ones of these
// are resolved at start.
const RuleVulnKEV = "vuln:kev"

const vulnRetiredNote = "Vulnerabilities no longer raise alerts. This one, with its risk score, is on the Vulnerabilities page. HomeXDR resolved this alert itself."

// retireVulnAlerts resolves the alerts older versions raised for vulnerabilities.
func (c *Core) retireVulnAlerts(ctx context.Context) {
	n, err := c.State.ResolveRuleAlerts(ctx, RuleVulnKEV, feedNoteAuthor, vulnRetiredNote)
	if err != nil {
		c.Log.Warn("vulnerabilities: resolve old alerts", "err", err)
		return
	}
	if n > 0 {
		c.Log.Info("vulnerabilities: resolved old alerts, which moved to the Vulnerabilities page", "count", n)
	}
}

// exposureDays is how far back the firewall log is read to see what the internet reaches.
const exposureDays = 7

// vulnExposure answers which hosts take connections from the internet: those the firewall
// passed connections to from public addresses in the last week (port forwards and other open
// inbound rules), with the ports.
type vulnExposure struct{ c *Core }

func (e vulnExposure) InternetExposure(ctx context.Context) (map[string][]int, error) {
	hosts, err := e.c.State.ListHosts(ctx, store.HostFilter{Kind: store.HostEndpoint})
	if err != nil {
		return nil, err
	}
	byIP := map[string]string{}
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		for _, ip := range h.IPs {
			byIP[ip] = h.ID
		}
		if h.LastIP != "" && !h.LastExternal {
			byIP[h.LastIP] = h.ID
		}
	}
	out := map[string][]int{}
	if len(byIP) == 0 {
		return out, nil
	}
	res, err := e.c.Events.Search(ctx, events.SearchQuery{From: time.Now().UTC().AddDate(0, 0, -exposureDays),
		Query: inboundBase + ` event.action:pass ` + notPrivateSource + ` | stats count by destination.ip, destination.port | head 5000`})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, row := range res.Rows {
		if len(row) < 2 {
			continue
		}
		hostID, ok := byIP[fmt.Sprint(row[0])]
		if !ok {
			continue
		}
		port, err := strconv.Atoi(fmt.Sprint(row[1]))
		if err != nil || port <= 0 {
			continue
		}
		k := hostID + ":" + strconv.Itoa(port)
		if !seen[k] {
			seen[k] = true
			out[hostID] = append(out[hostID], port)
		}
	}
	return out, nil
}
