package core

import (
	"context"
	"fmt"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

// RuleVulnKEV is the alert raised for software with a confirmed known-exploited vulnerability.
const RuleVulnKEV = "vuln:kev"

// vulnNotifier turns the vulnerability service's decisions into alerts.
type vulnNotifier struct{ c *Core }

func vulnEntity(hostID, cve string) string { return hostID + "/" + cve }

// RaiseVuln raises one finding per host and CVE.
func (n vulnNotifier) RaiseVuln(ctx context.Context, m store.VulnMatch) error {
	entity := vulnEntity(m.HostID, m.CVE)
	msg := fmt.Sprintf("%s runs %s %s, which has %s, a vulnerability CISA knows is being exploited. %s", m.Hostname, m.Package, m.Version, m.CVE, m.Reason)
	if m.Ransomware {
		msg += " It is known to be used in ransomware campaigns."
	}
	return n.c.RaiseFinding(ctx, Finding{
		RuleID: RuleVulnKEV, Severity: store.SevHigh, Tags: []string{"homexdr", "vulnerability", "kev"},
		Title:       "Known-exploited vulnerability on " + m.Hostname + ": " + m.CVE,
		Description: m.Title,
		Message:     msg,
		Entity:      entity, HostID: m.HostID, Hostname: m.Hostname, Dataset: "homexdr.vulnerability",
		Data: map[string]any{
			"entity": entity, "cve": m.CVE, "package": m.Package, "version": m.Version,
			"kev_date": m.KEVDate, "due_date": m.DueDate, "ransomware": m.Ransomware,
		},
	})
}

// ResolveVuln resolves a host and CVE's alert, with a note.
func (n vulnNotifier) ResolveVuln(ctx context.Context, hostID, cve, note string) error {
	_, err := n.c.State.ResolveFinding(ctx, RuleVulnKEV, hostID, vulnEntity(hostID, cve), feedNoteAuthor, note)
	return err
}
