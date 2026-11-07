//go:build windows

package windows

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Audit policy helpers for the process sensor's Security log source. The sensor only
// reads the policy and reports it in its status; the setters exist for `homexdr-agent
// install` and `uninstall`, which turn process auditing on and restore the previous
// state. A domain Group Policy that sets these values wins over local changes at its
// next refresh.

var (
	modadvapi32                = windows.NewLazySystemDLL("advapi32.dll")
	procAuditQuerySystemPolicy = modadvapi32.NewProc("AuditQuerySystemPolicy")
	procAuditSetSystemPolicy   = modadvapi32.NewProc("AuditSetSystemPolicy")
	procAuditFree              = modadvapi32.NewProc("AuditFree")
)

// Advanced audit policy subcategories the process sensor depends on.
var (
	// AuditProcessCreation is "Audit Process Creation" (Security event 4688).
	AuditProcessCreation = mustGUID("{0CCE922B-69AE-11D9-BED3-505054503030}")
	// AuditProcessTermination is "Audit Process Termination" (Security event 4689).
	AuditProcessTermination = mustGUID("{0CCE922C-69AE-11D9-BED3-505054503030}")
)

// The registry value behind the policy "Include command line in process creation
// events". When it is 1, event 4688 carries the command line.
const (
	cmdLineAuditKey   = `Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
	cmdLineAuditValue = "ProcessCreationIncludeCmdLine_Enabled"
)

// AuditFlags are the outcomes an audit subcategory records.
type AuditFlags uint32

// Audit flags (POLICY_AUDIT_EVENT_SUCCESS and POLICY_AUDIT_EVENT_FAILURE).
const (
	AuditNone    AuditFlags = 0
	AuditSuccess AuditFlags = 1
	AuditFailure AuditFlags = 2
)

// policyAuditEventNone is POLICY_AUDIT_EVENT_NONE: AuditSetSystemPolicy treats 0 as
// "leave unchanged", so turning a subcategory off needs this value.
const policyAuditEventNone = 4

// String returns "none", "success", "failure" or "success and failure".
func (f AuditFlags) String() string {
	switch f & (AuditSuccess | AuditFailure) {
	case AuditSuccess:
		return "success"
	case AuditFailure:
		return "failure"
	case AuditSuccess | AuditFailure:
		return "success and failure"
	}
	return "none"
}

// auditPolicyInformation is AUDIT_POLICY_INFORMATION.
type auditPolicyInformation struct {
	AuditSubCategoryGUID windows.GUID
	AuditingInformation  uint32
	AuditCategoryGUID    windows.GUID
}

// ProcessAudit is the audit configuration behind Security events 4688 and 4689.
type ProcessAudit struct {
	Creation    AuditFlags // Audit Process Creation
	Termination AuditFlags // Audit Process Termination
	// CommandLine is true when ProcessCreationIncludeCmdLine_Enabled is 1.
	CommandLine bool
	// CommandLineSet is false when the registry value does not exist (the Windows
	// default: no command lines). Setting a ProcessAudit with CommandLineSet false
	// deletes the value, so a saved state restores exactly.
	CommandLineSet bool
}

// QueryProcessAudit reads the process audit configuration. Reading the audit policy
// needs SeSecurityPrivilege (Administrators, SYSTEM); the registry value is readable by
// everyone. Fields that could be read are filled even when err is not nil.
func QueryProcessAudit() (ProcessAudit, error) {
	var p ProcessAudit
	var errs []error
	flags, err := QueryAuditSubcategories(AuditProcessCreation, AuditProcessTermination)
	if err != nil {
		errs = append(errs, err)
	} else {
		p.Creation, p.Termination = flags[0], flags[1]
	}
	if p.CommandLine, p.CommandLineSet, err = QueryCommandLineAuditing(); err != nil {
		errs = append(errs, err)
	}
	return p, errors.Join(errs...)
}

// SetProcessAudit applies p and returns the state before the change. The sensor never
// calls it.
func SetProcessAudit(p ProcessAudit) (prev ProcessAudit, err error) {
	prev, err = QueryProcessAudit()
	if err != nil {
		return prev, fmt.Errorf("read current audit policy: %w", err)
	}
	if _, err := SetAuditSubcategory(AuditProcessCreation, p.Creation); err != nil {
		return prev, err
	}
	if _, err := SetAuditSubcategory(AuditProcessTermination, p.Termination); err != nil {
		return prev, err
	}
	if _, _, err := SetCommandLineAuditing(p.CommandLine, p.CommandLineSet); err != nil {
		return prev, err
	}
	return prev, nil
}

// EnableProcessAudit turns on success auditing of process creation and termination
// (keeping failure auditing if it is on) and command lines in 4688, and returns the
// previous state for SetProcessAudit to restore. The sensor never calls it.
func EnableProcessAudit() (prev ProcessAudit, err error) {
	cur, err := QueryProcessAudit()
	if err != nil {
		return cur, fmt.Errorf("read current audit policy: %w", err)
	}
	return SetProcessAudit(ProcessAudit{
		Creation:       cur.Creation | AuditSuccess,
		Termination:    cur.Termination | AuditSuccess,
		CommandLine:    true,
		CommandLineSet: true,
	})
}

// QueryAuditSubcategories returns the system audit setting of each subcategory, in the
// order given.
func QueryAuditSubcategories(guids ...windows.GUID) ([]AuditFlags, error) {
	if len(guids) == 0 {
		return nil, nil
	}
	out := make([]AuditFlags, len(guids))
	err := withSecurityPrivilege(func() error {
		var p *auditPolicyInformation
		r, _, e := procAuditQuerySystemPolicy.Call(uintptr(unsafe.Pointer(&guids[0])), uintptr(len(guids)), uintptr(unsafe.Pointer(&p)))
		if byte(r) == 0 {
			return e
		}
		defer procAuditFree.Call(uintptr(unsafe.Pointer(p)))
		got := unsafe.Slice(p, len(guids))
		for i, g := range guids {
			for _, in := range got {
				if in.AuditSubCategoryGUID == g {
					out[i] = AuditFlags(in.AuditingInformation) & (AuditSuccess | AuditFailure)
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("query audit policy: %w", err)
	}
	return out, nil
}

// SetAuditSubcategory sets one subcategory of the system audit policy and returns its
// previous setting. The sensor never calls it.
func SetAuditSubcategory(guid windows.GUID, flags AuditFlags) (prev AuditFlags, err error) {
	cur, err := QueryAuditSubcategories(guid)
	if err != nil {
		return 0, err
	}
	prev = cur[0]
	info := auditPolicyInformation{AuditSubCategoryGUID: guid, AuditingInformation: uint32(flags & (AuditSuccess | AuditFailure))}
	if info.AuditingInformation == 0 {
		info.AuditingInformation = policyAuditEventNone
	}
	err = withSecurityPrivilege(func() error {
		r, _, e := procAuditSetSystemPolicy.Call(uintptr(unsafe.Pointer(&info)), 1)
		if byte(r) == 0 {
			return e
		}
		return nil
	})
	if err != nil {
		return prev, fmt.Errorf("set audit policy: %w", err)
	}
	return prev, nil
}

// QueryCommandLineAuditing reads ProcessCreationIncludeCmdLine_Enabled. set is false
// when the value does not exist.
func QueryCommandLineAuditing() (enabled, set bool, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, cmdLineAuditKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("read %s: %w", cmdLineAuditValue, err)
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(cmdLineAuditValue)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("read %s: %w", cmdLineAuditValue, err)
	}
	return v == 1, true, nil
}

// SetCommandLineAuditing writes ProcessCreationIncludeCmdLine_Enabled (1 or 0), or
// deletes it when set is false, and returns the previous state. The sensor never calls
// it.
func SetCommandLineAuditing(enabled, set bool) (prevEnabled, prevSet bool, err error) {
	prevEnabled, prevSet, err = QueryCommandLineAuditing()
	if err != nil {
		return false, false, err
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, cmdLineAuditKey, registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return prevEnabled, prevSet, fmt.Errorf("open %s: %w", cmdLineAuditKey, err)
	}
	defer k.Close()
	switch {
	case !set:
		if err := k.DeleteValue(cmdLineAuditValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return prevEnabled, prevSet, fmt.Errorf("delete %s: %w", cmdLineAuditValue, err)
		}
	case enabled:
		err = k.SetDWordValue(cmdLineAuditValue, 1)
	default:
		err = k.SetDWordValue(cmdLineAuditValue, 0)
	}
	if err != nil {
		return prevEnabled, prevSet, fmt.Errorf("set %s: %w", cmdLineAuditValue, err)
	}
	return prevEnabled, prevSet, nil
}

// withSecurityPrivilege runs fn with SeSecurityPrivilege enabled on an impersonation
// copy of the agent's own token, on a locked OS thread, so the process token is left
// as it is. If the privilege cannot be enabled, fn still runs (and fails with access
// denied when the account lacks the right).
func withSecurityPrivilege(fn func() error) error {
	runtime.LockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		return fn()
	}
	defer func() {
		// Only hand the thread back to the scheduler once it no longer impersonates.
		if windows.RevertToSelf() == nil {
			runtime.UnlockOSThread()
		}
	}()
	var tok windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &tok); err == nil {
		_ = enablePrivilege(tok, "SeSecurityPrivilege")
		tok.Close()
	}
	return fn()
}

func enablePrivilege(tok windows.Token, name string) error {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	return windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return g
}
