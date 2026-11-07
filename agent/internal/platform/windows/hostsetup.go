//go:build windows

package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// auditBackupName holds the audit configuration from before the first install, next to
// the config file, so uninstall can put it back. It is written once: reinstalling must
// not replace the original state with the one the first install set.
const auditBackupName = "audit-before-install.json"

func auditBackupPath() string {
	return filepath.Join(filepath.Dir((&Platform{}).Paths().ConfigFile), auditBackupName)
}

// SetupHost implements platform.HostSetup: it turns on the auditing the Security-log
// process source needs (process creation and termination, command lines in 4688).
// Sysmon, when installed, does not need it, but enabling it keeps the fallback working.
func (p *Platform) SetupHost() ([]string, error) {
	prev, err := EnableProcessAudit()
	if err != nil {
		return nil, fmt.Errorf("enable process auditing: %w", err)
	}
	path := auditBackupPath()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		b, _ := json.MarshalIndent(prev, "", "  ")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, fmt.Errorf("save previous audit policy: %w", err)
		}
		_ = p.ProtectPath(path)
	}
	cur, err := QueryProcessAudit()
	if err != nil {
		return nil, err
	}
	return describeAuditChange(prev, cur), nil
}

// RestoreHost implements platform.HostSetup: it restores the audit configuration saved
// by the first SetupHost, if any.
func (*Platform) RestoreHost() ([]string, error) {
	path := auditBackupPath()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var saved ProcessAudit
	if err := json.Unmarshal(b, &saved); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	prev, err := SetProcessAudit(saved)
	if err != nil {
		return nil, fmt.Errorf("restore audit policy: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	return describeAuditChange(prev, saved), nil
}

func describeAuditChange(from, to ProcessAudit) []string {
	var out []string
	if from.Creation != to.Creation {
		out = append(out, fmt.Sprintf("audit policy: Process Creation %s -> %s", from.Creation, to.Creation))
	}
	if from.Termination != to.Termination {
		out = append(out, fmt.Sprintf("audit policy: Process Termination %s -> %s", from.Termination, to.Termination))
	}
	if from.CommandLine != to.CommandLine || from.CommandLineSet != to.CommandLineSet {
		out = append(out, fmt.Sprintf("audit policy: command lines in event 4688 %s -> %s", onOff(from.CommandLine), onOff(to.CommandLine)))
	}
	if len(out) == 0 {
		out = append(out, "audit policy: process auditing already as needed, nothing changed")
	}
	return out
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
