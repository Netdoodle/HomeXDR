//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/appcontrol"
	"github.com/Netdoodle/homexdr/shared/api"
)

// AppControl applies or removes HomeXDR's App Control policy. The XML is built by the
// appcontrol package, compiled with ConvertFrom-CIPolicy (the ConfigCI module that ships
// with Windows) and activated with CiTool, which needs no reboot (Windows 11 22H2 and
// later). Only HomeXDR's own policy ID is ever touched.
func (p *Platform) AppControl(ctx context.Context, prm api.AppControlParams) (api.AppControlResult, error) {
	if err := appcontrol.Validate(prm); err != nil {
		return api.AppControlResult{}, err
	}
	res := api.AppControlResult{Mode: prm.Mode, Version: prm.Version, Rules: len(prm.Rules)}
	if prm.Mode == api.AppControlOff || len(prm.Rules) == 0 {
		removed, err := removeAppControl(ctx)
		if err != nil {
			return res, err
		}
		res.Rules = 0
		switch {
		case removed && prm.Mode == api.AppControlOff:
			res.Message = "HomeXDR's App Control policy was removed"
		case removed:
			res.Message = "nothing to block: HomeXDR's App Control policy was removed"
		default:
			res.Message = "no HomeXDR App Control policy is active"
		}
		return res, nil
	}
	if _, err := exec.LookPath(ciTool()); err != nil {
		return res, fmt.Errorf("CiTool.exe is missing: App Control policies without a reboot need Windows 11 22H2 or later")
	}
	dir := filepath.Join(p.Paths().DataDir, "appcontrol")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return res, err
	}
	xmlPath := filepath.Join(dir, "homexdr-policy.xml")
	binPath := filepath.Join(dir, strings.Trim(api.AppControlPolicyID, "{}")+".cip")
	if err := os.WriteFile(xmlPath, appcontrol.PolicyXML(prm, time.Now()), 0o600); err != nil {
		return res, err
	}
	// Both paths are the agent's own files; they go in as single-quoted literals.
	script := fmt.Sprintf("$ErrorActionPreference='Stop'\nImport-Module ConfigCI\nConvertFrom-CIPolicy -XmlFilePath '%s' -BinaryFilePath '%s' | Out-Null\n",
		psQuote(xmlPath), psQuote(binPath))
	if _, err := runPowerShell(ctx, script); err != nil {
		return res, fmt.Errorf("compile the policy: %w", err)
	}
	if out, err := exec.CommandContext(ctx, ciTool(), "--update-policy", binPath, "-json").CombinedOutput(); err != nil {
		return res, fmt.Errorf("CiTool --update-policy: %w: %s", err, trimOutput(string(out)))
	}
	pol, err := findAppControl(ctx)
	if err != nil {
		return res, err
	}
	if pol == nil || !pol.IsEnforced {
		return res, fmt.Errorf("the policy was accepted but is not active (CiTool --list-policies)")
	}
	what := "Windows now refuses to run"
	if prm.Mode == api.AppControlAudit {
		what = "audit mode: Windows logs (CodeIntegrity event 3076) but still runs"
	}
	res.Message = fmt.Sprintf("%s %d blocked file(s); policy version %s", what, len(prm.Rules), pol.Version)
	return res, nil
}

func ciTool() string { return filepath.Join(os.Getenv("SystemRoot"), `System32\CiTool.exe`) }

func psQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

type ciPolicy struct {
	PolicyID     string `json:"PolicyID"`
	FriendlyName string `json:"FriendlyName"`
	Version      string `json:"VersionString"`
	IsEnforced   bool   `json:"IsEnforced"`
	IsOnDisk     bool   `json:"IsOnDisk"`
}

// findAppControl returns HomeXDR's policy as CiTool lists it, or nil.
func findAppControl(ctx context.Context) (*ciPolicy, error) {
	out, err := exec.CommandContext(ctx, ciTool(), "--list-policies", "-json").Output()
	if err != nil {
		return nil, fmt.Errorf("CiTool --list-policies: %w", err)
	}
	var list struct {
		Policies []ciPolicy `json:"Policies"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("CiTool --list-policies: %w", err)
	}
	want := strings.ToLower(strings.Trim(api.AppControlPolicyID, "{}"))
	for i, pol := range list.Policies {
		if strings.ToLower(strings.Trim(pol.PolicyID, "{}")) == want {
			return &list.Policies[i], nil
		}
	}
	return nil, nil
}

// removeAppControl removes HomeXDR's policy if it is there.
func removeAppControl(ctx context.Context) (bool, error) {
	pol, err := findAppControl(ctx)
	if err != nil || pol == nil {
		return false, err
	}
	if out, err := exec.CommandContext(ctx, ciTool(), "--remove-policy", api.AppControlPolicyID, "-json").CombinedOutput(); err != nil {
		return false, fmt.Errorf("CiTool --remove-policy: %w: %s", err, trimOutput(string(out)))
	}
	if pol, err := findAppControl(ctx); err == nil && pol != nil && pol.IsEnforced {
		return false, fmt.Errorf("CiTool removed the policy but it is still active")
	}
	return true, nil
}
