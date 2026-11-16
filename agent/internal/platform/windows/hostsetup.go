//go:build windows

package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// auditBackupName holds the audit configuration from before the first install, next to
// the config file, so uninstall can put it back. It is written once: reinstalling must
// not replace the original state with the one the first install set.
const auditBackupName = "audit-before-install.json"

// taskSchedulerChannel is off by default; the eventlog sensor lists it and reports
// "degraded" while it cannot be read.
const taskSchedulerChannel = "Microsoft-Windows-TaskScheduler/Operational"

// auditBackup is the content of the backup file: the process audit state (its fields are
// at the top level, as in files from older versions) plus the earlier state of the Task
// Scheduler log. Files without TaskSchedulerLog stay valid.
type auditBackup struct {
	ProcessAudit
	// TaskSchedulerLog records whether the Task Scheduler operational log was enabled
	// before install. Nil when unknown (old file).
	TaskSchedulerLog *bool `json:"TaskSchedulerLogWasEnabled,omitempty"`
}

func parseAuditBackup(b []byte) (auditBackup, error) {
	var a auditBackup
	err := json.Unmarshal(b, &a)
	return a, err
}

func auditBackupPath() string {
	return filepath.Join(filepath.Dir((&Platform{}).Paths().ConfigFile), auditBackupName)
}

// SetupHost implements platform.HostSetup: it turns on the auditing the Security-log
// process source needs (process creation and termination, command lines in 4688) and
// the Task Scheduler operational log. Sysmon, when installed, does not need the audit
// settings, but enabling them keeps the fallback working.
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
		bk := auditBackup{ProcessAudit: prev}
		if was, err := channelEnabled(taskSchedulerChannel); err == nil {
			bk.TaskSchedulerLog = &was
		}
		b, _ := json.MarshalIndent(bk, "", "  ")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, fmt.Errorf("save previous audit policy: %w", err)
		}
		_ = p.ProtectPath(path)
	}
	cur, err := QueryProcessAudit()
	if err != nil {
		return nil, err
	}
	out := describeAuditChange(prev, cur)
	line, err := enableTaskLog()
	if line != "" {
		out = append(out, line)
	}
	return out, err
}

// enableTaskLog turns the Task Scheduler operational log on if it is off.
func enableTaskLog() (string, error) {
	on, err := channelEnabled(taskSchedulerChannel)
	if err != nil {
		return "", fmt.Errorf("read Task Scheduler log state: %w", err)
	}
	if on {
		return "Task Scheduler operational log: already on", nil
	}
	if err := setChannelEnabled(taskSchedulerChannel, true); err != nil {
		return "", fmt.Errorf("enable Task Scheduler log: %w", err)
	}
	return "Task Scheduler operational log: off -> on", nil
}

// StartupSetup implements platform.StartupSetup. Installs from before the Task
// Scheduler log was handled have a backup file without that field: record the current
// state in it and turn the log on, once. Only SYSTEM does this; it is best-effort.
func (p *Platform) StartupSetup(log *slog.Logger) {
	if !runningAsSystem() {
		return
	}
	path := auditBackupPath()
	b, err := os.ReadFile(path)
	if err != nil {
		return // no backup: not installed through `install`, nothing to extend
	}
	bk, err := parseAuditBackup(b)
	if err != nil || bk.TaskSchedulerLog != nil {
		return
	}
	was, err := channelEnabled(taskSchedulerChannel)
	if err != nil {
		log.Warn("task scheduler log: cannot read state", "err", err)
		return
	}
	bk.TaskSchedulerLog = &was
	nb, _ := json.MarshalIndent(bk, "", "  ")
	if err := os.WriteFile(path, nb, 0o600); err != nil {
		log.Warn("task scheduler log: cannot update backup", "err", err)
		return
	}
	_ = p.ProtectPath(path)
	if !was {
		if err := setChannelEnabled(taskSchedulerChannel, true); err != nil {
			log.Warn("task scheduler log: cannot enable", "err", err)
			return
		}
		log.Info("task scheduler log: enabled the operational log")
	}
}

func runningAsSystem() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	return u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// RestoreHost implements platform.HostSetup: it restores the audit configuration saved
// by the first SetupHost, if any, and turns the Task Scheduler log off again when it
// was off before.
func (*Platform) RestoreHost() ([]string, error) {
	path := auditBackupPath()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bk, err := parseAuditBackup(b)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	saved := bk.ProcessAudit
	prev, err := SetProcessAudit(saved)
	if err != nil {
		return nil, fmt.Errorf("restore audit policy: %w", err)
	}
	out := describeAuditChange(prev, saved)
	if bk.TaskSchedulerLog != nil && !*bk.TaskSchedulerLog {
		if err := setChannelEnabled(taskSchedulerChannel, false); err != nil {
			// Keep the file so a later uninstall can retry.
			return out, fmt.Errorf("disable Task Scheduler log: %w", err)
		}
		out = append(out, "Task Scheduler operational log: on -> off")
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	return out, nil
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
