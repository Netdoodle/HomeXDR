package windows

import "testing"

func TestEvaluateDCAudit(t *testing.T) {
	all := make([]uint32, len(dcAuditSpecs))
	for i, s := range dcAuditSpecs {
		all[i] = s.Wanted
	}
	if g := evaluateDCAudit(all); len(g) != 0 {
		t.Fatalf("fully audited: %+v", g)
	}

	// More auditing than wanted is fine.
	more := make([]uint32, len(dcAuditSpecs))
	for i := range more {
		more[i] = dcAuditSuccess | dcAuditFailure
	}
	if g := evaluateDCAudit(more); len(g) != 0 {
		t.Fatalf("over-audited: %+v", g)
	}

	// Nothing set: every subcategory is a gap, in spec order.
	g := evaluateDCAudit(nil)
	if len(g) != len(dcAuditSpecs) || g[0].Subcategory != "Credential Validation" || g[0].Current != "none" || g[0].Wanted != "success and failure" {
		t.Fatalf("empty policy: %+v", g)
	}

	// Success only where success and failure are wanted, and failure only where success is.
	cur := append([]uint32(nil), all...)
	cur[0] = dcAuditSuccess // Credential Validation wants both
	cur[3] = dcAuditFailure // Computer Account Management wants success
	g = evaluateDCAudit(cur)
	if len(g) != 2 {
		t.Fatalf("partial: %+v", g)
	}
	if g[0].Subcategory != "Credential Validation" || g[0].Current != "success" || g[0].GUID != "{0CCE923F-69AE-11D9-BED3-505054503030}" {
		t.Errorf("gap 0: %+v", g[0])
	}
	if g[1].Subcategory != "Computer Account Management" || g[1].Wanted != "success" || g[1].Current != "failure" {
		t.Errorf("gap 1: %+v", g[1])
	}
}

func TestDCAuditSpecsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range dcAuditSpecs {
		if seen[s.GUID] || seen[s.Name] || s.Wanted == 0 {
			t.Errorf("bad spec %+v", s)
		}
		seen[s.GUID], seen[s.Name] = true, true
	}
}
