package core

import (
	"context"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/detect"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/communityid"
	"github.com/Netdoodle/homexdr/shared/event"
)

// maxClockSkew is how far in the future an event timestamp may be before it is clamped.
const maxClockSkew = 5 * time.Minute

// Ingest normalizes events from a host, stores them, then runs detection. It returns an
// error only if storing fails, so the sender can retry.
func (c *Core) Ingest(ctx context.Context, host *store.Host, evs []*event.Event) error {
	if len(evs) == 0 {
		return nil
	}
	now := time.Now().UTC()
	for _, e := range evs {
		c.normalize(e, host, now)
	}
	if err := c.Events.Insert(ctx, evs); err != nil {
		return err
	}
	for _, e := range evs {
		c.detect(ctx, e)
	}
	return nil
}

func (c *Core) normalize(e *event.Event, h *store.Host, now time.Time) {
	if e.ID == "" || len(e.ID) > 64 {
		e.ID = event.NewID()
	}
	if e.Timestamp.IsZero() || e.Timestamp.After(now.Add(maxClockSkew)) {
		e.Timestamp = now
	}
	e.Timestamp = e.Timestamp.UTC()
	e.Agent.ID = h.ID
	if h.Kind == store.HostNetwork {
		e.Agent.Type = event.AgentTypeSyslog
	} else {
		e.Agent.Type = event.AgentTypeEndpoint
	}
	os := h.OS
	e.Host.ID = h.ID
	e.Host.Name = h.Hostname
	e.Host.OS = &os
	if len(e.Host.IP) == 0 {
		e.Host.IP = h.IPs
	}
	if e.Host.Arch == "" {
		e.Host.Arch = h.Arch
	}
	e.Event.Ingested = &now
	if e.Event.Kind == "" {
		e.Event.Kind = event.KindEvent
	}
	if e.Network != nil && e.Network.CommunityID == "" && e.Source != nil && e.Destination != nil {
		e.Network.CommunityID = communityid.ComputeStrings(
			e.Source.IP, e.Destination.IP, e.Network.Transport, e.Source.Port, e.Destination.Port)
	}
}

func (c *Core) detect(ctx context.Context, e *event.Event) {
	for _, r := range c.Engine.Evaluate(e) {
		in := store.AlertInput{
			Rule: store.AlertRule{
				ID: r.ID, Title: r.Title, Description: r.Description, Level: r.Level,
				Tags: r.Tags, References: r.References, FalsePositives: r.FalsePositives,
			},
			Mitre:    toStoreMitre(detect.MitreFromTags(r.Tags)),
			Severity: r.Level,
			Event:    e,
		}
		c.recordAlert(ctx, in)
	}
	// IDS alerts (Suricata) become alerts directly.
	if e.Event.Kind == event.KindAlert && e.Rule != nil && e.Event.Module == event.ModuleSuricata {
		sev := store.SevLow
		switch {
		case e.Event.Severity >= 73:
			sev = store.SevHigh
		case e.Event.Severity >= 47:
			sev = store.SevMedium
		}
		tags := []string{"suricata"}
		if e.Rule.Category != "" {
			tags = append(tags, strings.ToLower(strings.ReplaceAll(e.Rule.Category, " ", "_")))
		}
		c.recordAlert(ctx, store.AlertInput{
			Rule: store.AlertRule{
				ID: "suricata:" + e.Rule.ID, Title: e.Rule.Name, Description: e.Rule.Category,
				Level: sev, Tags: tags,
			},
			Severity: sev,
			Event:    e,
		})
	}
}

func (c *Core) recordAlert(ctx context.Context, in store.AlertInput) {
	a, isNew, err := c.State.RecordAlert(ctx, in)
	if err != nil {
		c.Log.Error("record alert", "err", err, "rule", in.Rule.ID)
		return
	}
	if isNew {
		c.Log.Info("alert", "id", a.ID, "rule", in.Rule.Title, "severity", a.Severity, "host", a.Hostname)
	}
}

func toStoreMitre(m []detect.Mitre) []store.Mitre {
	out := make([]store.Mitre, len(m))
	for i, v := range m {
		out[i] = store.Mitre{Tactic: v.Tactic, TechniqueID: v.TechniqueID, Technique: v.Technique}
	}
	return out
}
