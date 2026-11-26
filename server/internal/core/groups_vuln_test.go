package core

import (
	"context"
	"testing"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

func TestResolveVulnManagementInherits(t *testing.T) {
	c := newRepoTestCore(t)
	ctx := context.Background()
	parent, err := c.State.CreateGroup(ctx, "Lab", "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := c.State.CreateGroup(ctx, "Red Team", parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ReloadGroups(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.ResolveVulnManagement(child.ID); !got.Value || got.GroupID != "" {
		t.Fatalf("default must be on: %+v", got)
	}
	off, on := false, true
	if _, err := c.State.UpdateGroup(ctx, parent.ID, store.GroupUpdate{Policy: &store.GroupPolicy{Vuln: store.VulnGroupPolicy{Enabled: &off}}}); err != nil {
		t.Fatal(err)
	}
	_ = c.ReloadGroups(ctx)
	if got := c.ResolveVulnManagement(child.ID); got.Value || got.GroupID != parent.ID {
		t.Fatalf("child must inherit off from the parent: %+v", got)
	}
	if _, err := c.State.UpdateGroup(ctx, child.ID, store.GroupUpdate{Policy: &store.GroupPolicy{Vuln: store.VulnGroupPolicy{Enabled: &on}}}); err != nil {
		t.Fatal(err)
	}
	_ = c.ReloadGroups(ctx)
	if got := c.ResolveVulnManagement(child.ID); !got.Value || got.GroupID != child.ID {
		t.Fatalf("child override: %+v", got)
	}
	if got := c.ResolveVulnManagement(parent.ID); got.Value {
		t.Fatalf("parent: %+v", got)
	}
	if got := c.ResolveVulnManagement(""); !got.Value {
		t.Fatalf("ungrouped: %+v", got)
	}
	if !c.Health.Vuln.Excluded(parent.ID) || c.Health.Vuln.Excluded(child.ID) {
		t.Fatal("scan hook out of step with the policy")
	}
}
