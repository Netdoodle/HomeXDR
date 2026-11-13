package appcontrol

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

func TestPolicyXML(t *testing.T) {
	h256 := strings.Repeat("ab", 32)
	p := api.AppControlParams{Mode: api.AppControlEnforce, Version: "v1", Rules: []api.AppControlRule{
		{Name: `evil <"x">.exe`, SHA256: h256, SHA1: strings.Repeat("cd", 20)},
		{SHA256: strings.Repeat("ef", 32)},
	}}
	if err := Validate(p); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	out := PolicyXML(p, now)
	var doc struct {
		XMLName   xml.Name `xml:"SiPolicy"`
		VersionEx string
		PolicyID  string
		Rules     []struct{ Option string } `xml:"Rules>Rule"`
		Deny      []struct {
			ID   string `xml:"ID,attr"`
			Hash string `xml:"Hash,attr"`
		} `xml:"FileRules>Deny"`
		Scenarios []struct {
			Value string   `xml:"Value,attr"`
			Refs  []string `xml:"ProductSigners>FileRulesRef>FileRuleRef>RuleID"`
		} `xml:"SigningScenarios>SigningScenario"`
	}
	if err := xml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("not valid XML: %v\n%s", err, out)
	}
	if doc.PolicyID != api.AppControlPolicyID || len(doc.Deny) != 3 || doc.Deny[0].Hash != strings.ToUpper(h256) {
		t.Fatalf("policy = %+v", doc)
	}
	var opts []string
	for _, r := range doc.Rules {
		opts = append(opts, r.Option)
	}
	if strings.Contains(strings.Join(opts, ","), "Audit Mode") || !strings.Contains(strings.Join(opts, ","), "Disabled:Script Enforcement") {
		t.Fatalf("enforce options = %v", opts)
	}
	if !strings.Contains(string(PolicyXML(api.AppControlParams{Mode: api.AppControlAudit}, now)), "Enabled:Audit Mode") {
		t.Fatal("audit policy without audit mode")
	}
	if VersionEx(now.Add(time.Hour)) <= VersionEx(now) && VersionEx(now.Add(time.Hour)) == VersionEx(now) {
		t.Fatal("version does not grow")
	}
	for _, bad := range []api.AppControlParams{
		{Mode: "block"},
		{Mode: api.AppControlEnforce, Rules: []api.AppControlRule{{SHA256: "XYZ"}}},
		{Mode: api.AppControlEnforce, Rules: []api.AppControlRule{{SHA256: strings.ToUpper(h256)}}},
		{Mode: api.AppControlEnforce, Version: "a b"},
	} {
		if Validate(bad) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
