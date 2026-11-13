// Package appcontrol builds HomeXDR's Windows App Control (WDAC) policy: a base policy
// that allows everything and denies a list of files by Authenticode hash. It has no
// Windows dependencies, so it is tested everywhere; the Windows platform compiles and
// applies the XML (ConvertFrom-CIPolicy, CiTool).
package appcontrol

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
)

var (
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sha1Re   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// versionRe keeps the version printable in a result and a file name.
	versionRe = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)
)

// Validate checks a command's parameters before anything runs.
func Validate(p api.AppControlParams) error {
	switch p.Mode {
	case api.AppControlOff, api.AppControlAudit, api.AppControlEnforce:
	default:
		return fmt.Errorf("unknown App Control mode %q", p.Mode)
	}
	if !versionRe.MatchString(p.Version) {
		return fmt.Errorf("invalid version %q", p.Version)
	}
	if len(p.Rules) > api.AppControlMaxRules {
		return fmt.Errorf("at most %d rules", api.AppControlMaxRules)
	}
	for i, r := range p.Rules {
		if !sha256Re.MatchString(r.SHA256) {
			return fmt.Errorf("rule %d: sha256 must be 64 lower-case hex characters", i)
		}
		if r.SHA1 != "" && !sha1Re.MatchString(r.SHA1) {
			return fmt.Errorf("rule %d: sha1 must be 40 lower-case hex characters", i)
		}
	}
	return nil
}

// VersionEx is a policy version that grows with time (Windows refuses to replace a
// policy with a lower version): 10.0.<high 16 bits>.<low 16 bits> of the seconds since
// 2026-01-01.
func VersionEx(now time.Time) string {
	t := uint32(max(now.Unix()-1767225600, 0))
	return fmt.Sprintf("10.0.%d.%d", t>>16, t&0xffff)
}

// PolicyXML is the policy for p (audit or enforce), in the format ConvertFrom-CIPolicy
// reads.
func PolicyXML(p api.AppControlParams, now time.Time) []byte {
	var b bytes.Buffer
	esc := func(s string) string {
		var e bytes.Buffer
		_ = xml.EscapeText(&e, []byte(s))
		return e.String()
	}
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	w(`<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">` + "\n")
	w("  <VersionEx>%s</VersionEx>\n", VersionEx(now))
	w("  <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>\n")
	w("  <PolicyID>%s</PolicyID>\n  <BasePolicyID>%s</BasePolicyID>\n", api.AppControlPolicyID, api.AppControlPolicyID)
	w("  <Rules>\n")
	options := []string{
		"Enabled:Unsigned System Integrity Policy", // HomeXDR does not sign policies
		"Enabled:UMCI",                    // apply to user-mode programs, not only drivers
		"Enabled:Update Policy No Reboot", // later versions replace it without a reboot
		"Disabled:Script Enforcement",     // block executables only; leave PowerShell's language mode alone
	}
	if p.Mode == api.AppControlAudit {
		options = append(options, "Enabled:Audit Mode")
	}
	for _, o := range options {
		w("    <Rule>\n      <Option>%s</Option>\n    </Rule>\n", o)
	}
	w("  </Rules>\n  <EKUs />\n  <FileRules>\n")
	w(`    <Allow ID="ID_ALLOW_A_1" FriendlyName="Allow kernel drivers" FileName="*" />` + "\n")
	w(`    <Allow ID="ID_ALLOW_A_2" FriendlyName="Allow user mode programs" FileName="*" />` + "\n")
	var refs []string
	for i, r := range p.Rules {
		name := r.Name
		if name == "" {
			name = r.SHA256[:16]
		}
		name = esc(strings.Map(func(c rune) rune {
			if c < 0x20 {
				return ' '
			}
			return c
		}, name))
		id := fmt.Sprintf("ID_DENY_HX_%d", i+1)
		w(`    <Deny ID="%s_SHA256" FriendlyName="HomeXDR: %s (SHA256)" Hash="%s" />`+"\n", id, name, strings.ToUpper(r.SHA256))
		refs = append(refs, id+"_SHA256")
		if r.SHA1 != "" {
			w(`    <Deny ID="%s_SHA1" FriendlyName="HomeXDR: %s (SHA1)" Hash="%s" />`+"\n", id, name, strings.ToUpper(r.SHA1))
			refs = append(refs, id+"_SHA1")
		}
	}
	w("  </FileRules>\n  <Signers />\n  <SigningScenarios>\n")
	w(`    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS_1" FriendlyName="Kernel mode">` + "\n")
	w("      <ProductSigners>\n        <FileRulesRef>\n          <FileRuleRef RuleID=\"ID_ALLOW_A_1\" />\n        </FileRulesRef>\n      </ProductSigners>\n    </SigningScenario>\n")
	w(`    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User mode">` + "\n")
	w("      <ProductSigners>\n        <FileRulesRef>\n          <FileRuleRef RuleID=\"ID_ALLOW_A_2\" />\n")
	for _, r := range refs {
		w("          <FileRuleRef RuleID=\"%s\" />\n", r)
	}
	w("        </FileRulesRef>\n      </ProductSigners>\n    </SigningScenario>\n  </SigningScenarios>\n")
	w("  <UpdatePolicySigners />\n  <CiSigners />\n  <HvciOptions>0</HvciOptions>\n  <Settings>\n")
	w(`    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">` + "\n      <Value>\n        <String>HomeXDR block list</String>\n      </Value>\n    </Setting>\n")
	w(`    <Setting Provider="PolicyInfo" Key="Information" ValueName="Id">`+"\n      <Value>\n        <String>%s</String>\n      </Value>\n    </Setting>\n", esc(p.Version))
	w("  </Settings>\n</SiPolicy>\n")
	return b.Bytes()
}
