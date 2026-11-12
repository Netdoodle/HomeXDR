package core

import (
	"context"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// ServerHostID is the host ID of alerts about HomeXDR itself or about the network as a
// whole, which belong to no registered host.
const ServerHostID = "homexdr-server"

// Finding is something the server worked out itself, as opposed to a rule matching one
// event: a silent data source, a new device, a beaconing pattern.
type Finding struct {
	// RuleID is stable per kind of finding, such as "health:feed-silent".
	RuleID      string
	Title       string
	Description string
	Severity    string // store.SevHigh and so on
	Tags        []string
	// Entity is what repeats have in common; repeats fold into one open alert.
	Entity string
	// HostID and Hostname name a registered host; empty means the server itself.
	HostID, Hostname string
	// Dataset is the event's event.dataset, such as "homexdr.health".
	Dataset string
	Message string
	// Source and Destination, when known, make the alert searchable by address.
	Source, Destination *event.Endpoint
	Data                map[string]any
	// LinkKey and LinkSource fold the finding with other detectors' alerts about the same
	// thing (store.AlertInput.LinkKey).
	LinkKey, LinkSource string
}

// RaiseFinding stores a finding as an event and sends it through the same path as a rule
// hit, so suppressions, notifications and the AI analyst treat them alike.
func (c *Core) RaiseFinding(ctx context.Context, f Finding) error {
	now := time.Now().UTC()
	hostID, hostname := f.HostID, f.Hostname
	if hostID == "" {
		hostID, hostname = ServerHostID, "HomeXDR"
	}
	ev := &event.Event{
		ID:        event.NewID(),
		Timestamp: now,
		Agent:     event.Agent{ID: hostID, Type: event.AgentTypeIntegration},
		Host:      event.Host{ID: hostID, Name: hostname},
		Event: event.Meta{
			Kind: event.KindAlert, Module: event.ModuleHomeXDR, Dataset: f.Dataset, Ingested: &now,
		},
		Message:     f.Message,
		Source:      f.Source,
		Destination: f.Destination,
		Data:        f.Data,
	}
	if err := c.Events.Insert(ctx, []*event.Event{ev}); err != nil {
		return err
	}
	c.recordAlert(ctx, store.AlertInput{
		Rule: store.AlertRule{
			ID: f.RuleID, Title: f.Title, Description: f.Description, Level: f.Severity, Tags: f.Tags,
		},
		Severity:    f.Severity,
		Event:       ev,
		DedupEntity: f.Entity,
		LinkKey:     f.LinkKey,
		LinkSource:  f.LinkSource,
	})
	return nil
}
