package core

import (
	"context"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

const testFP = "SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI"

func TestMaintenanceSSHKey(t *testing.T) {
	c := newRepoTestCore(t)
	ctx := context.Background()
	h, err := c.State.CreateEndpoint(ctx, "a", api.HostInfo{Hostname: "tower", OS: event.OS{Platform: "linux"}}, nil, "s1")
	if err != nil {
		t.Fatal(err)
	}
	login := &event.Event{
		Event:   event.Meta{Category: []string{event.CategoryAuthentication}, Action: "ssh_login", Outcome: event.OutcomeSuccess, Module: event.ModuleAuthLog},
		Process: &event.Process{PID: 1000, Name: "sshd-session"},
		User:    &event.User{Name: "root"},
		Source:  &event.Endpoint{IP: "192.168.10.52"},
		Labels:  map[string]string{"ssh_key": testFP},
	}
	exec := func() *event.Event {
		return &event.Event{
			Event:   event.Meta{Category: []string{event.CategoryProcess}, Action: "exec", Module: "procconn"},
			Process: &event.Process{PID: 1002, Name: "sed", CommandLine: "sed -i s/a/b/ /etc/x"},
			Labels:  map[string]string{"ssh_session": "1000"},
		}
	}
	e1 := exec()
	if err := c.Ingest(ctx, h, []*event.Event{login, e1}); err != nil {
		t.Fatal(err)
	}
	if e1.Labels["ssh_key"] != testFP || e1.Labels["ssh_key_name"] != "" {
		t.Fatalf("labels before naming = %v", e1.Labels)
	}

	v, err := c.MaintenanceView(ctx, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.SSHKeys) != 1 || v.SSHKeys[0].Fingerprint != testFP || v.SSHKeys[0].Logins != 1 || len(v.SSHKeys[0].Hosts) != 1 {
		t.Fatalf("keys seen = %+v", v.SSHKeys)
	}
	if len(v.Sources) != 3 {
		t.Fatalf("sources = %+v", v.Sources)
	}

	if _, err := c.SaveMaintenance(ctx, MaintenanceInput{SSHKeys: []SSHKeyTag{{Fingerprint: testFP, Maintenance: true}}}, "admin"); err == nil {
		t.Fatal("maintenance on an unnamed key was accepted")
	}
	v, err = c.SaveMaintenance(ctx, MaintenanceInput{SSHKeys: []SSHKeyTag{{Fingerprint: testFP, Name: "Claude maintenance", Maintenance: true}}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !v.SSHKeys[0].Maintenance || v.SSHKeys[0].SuppressionID == "" {
		t.Fatalf("after save = %+v", v.SSHKeys[0])
	}

	e2 := exec()
	if err := c.Ingest(ctx, h, []*event.Event{e2}); err != nil {
		t.Fatal(err)
	}
	if e2.Labels["ssh_key_name"] != "Claude maintenance" {
		t.Fatalf("labels after naming = %v", e2.Labels)
	}
	in := store.AlertInput{Rule: store.AlertRule{ID: "r1", Title: "Sed on etc", Level: store.SevMedium}, Severity: store.SevMedium, Event: e2}
	if sup := c.Suppress.Check(ctx, in); sup == nil || sup.Overridden {
		t.Fatalf("maintenance did not suppress: %+v", sup)
	}
	crit := in
	crit.Severity = store.SevCritical
	if sup := c.Suppress.Check(ctx, crit); sup == nil || !sup.Overridden {
		t.Fatalf("a critical alert was not kept: %+v", sup)
	}
	other := exec()
	other.Labels = nil
	if sup := c.Suppress.Check(ctx, store.AlertInput{Rule: in.Rule, Severity: store.SevMedium, Event: other}); sup != nil {
		t.Fatalf("an unrelated command was suppressed: %+v", sup)
	}

	// Deleting the suppression on the Suppressions page turns maintenance off here.
	if err := c.DeleteSuppression(ctx, v.SSHKeys[0].SuppressionID, "admin"); err != nil {
		t.Fatal(err)
	}
	v, _ = c.MaintenanceView(ctx, 30)
	if v.SSHKeys[0].Maintenance || v.SSHKeys[0].Name != "Claude maintenance" {
		t.Fatalf("after deleting its suppression = %+v", v.SSHKeys[0])
	}

	// A source, with an end.
	end := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	v, err = c.SaveMaintenance(ctx, MaintenanceInput{
		SSHKeys: []SSHKeyTag{{Fingerprint: testFP, Name: "Claude maintenance"}},
		Sources: []MaintenanceSource{{ID: MaintDockerUpdate, Maintenance: true, ExpiresAt: &end}},
	}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	var docker MaintenanceSourceView
	for _, s := range v.Sources {
		if s.ID == MaintDockerUpdate {
			docker = s
		}
	}
	sp, err := c.State.GetSuppression(ctx, docker.SuppressionID)
	if err != nil || sp.ExpiresAt == nil || !sp.ExpiresAt.Equal(end) || sp.Conditions[0].Field != "labels.maintenance" {
		t.Fatalf("docker suppression = %+v, %v", sp, err)
	}
	if _, err := c.SaveMaintenance(ctx, MaintenanceInput{SSHKeys: []SSHKeyTag{{Fingerprint: "nope"}}}, "admin"); err == nil {
		t.Fatal("a bad fingerprint was accepted")
	}
}

func TestMaintenanceContainerStart(t *testing.T) {
	tr := newMaintTracker()
	now := time.Now()
	tr.started = now.Add(-time.Hour)
	ev := func() *event.Event {
		return &event.Event{Container: &event.Container{ID: "abc"}, Process: &event.Process{Name: "sed"}}
	}
	e := ev()
	tr.label(e, "h1", now)
	if e.Labels["maintenance"] != MaintContainerStart {
		t.Fatalf("new container: %v", e.Labels)
	}
	e = ev()
	tr.label(e, "h1", now.Add(6*time.Minute))
	if e.Labels["maintenance"] != "" {
		t.Fatalf("after the window: %v", e.Labels)
	}
	// Containers first seen right after HomeXDR starts may be old: not start-up.
	tr2 := newMaintTracker()
	e = ev()
	tr2.label(e, "h1", time.Now())
	if e.Labels["maintenance"] != "" {
		t.Fatalf("just after start: %v", e.Labels)
	}
	// The agent's label wins.
	e = &event.Event{Container: &event.Container{ID: "def"}, Labels: map[string]string{"maintenance": MaintDockerUpdate}}
	tr.label(e, "h1", now)
	if e.Labels["maintenance"] != MaintDockerUpdate {
		t.Fatalf("agent label replaced: %v", e.Labels)
	}
}
