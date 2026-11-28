//go:build windows

package windows

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Netdoodle/homexdr/shared/api"
)

// isDomainController reports whether the Active Directory Domain Services service
// (NTDS) is installed. A member server or workstation does not have it.
func isDomainController() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService("NTDS")
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// queryDCAuditGaps reads the system audit policy for the domain controller
// subcategories. It needs SeSecurityPrivilege (the agent runs as SYSTEM). On error it
// returns the error text so the console shows the check as unknown, not as passing.
func queryDCAuditGaps() ([]api.AuditGap, string) {
	guids := make([]windows.GUID, len(dcAuditSpecs))
	for i, s := range dcAuditSpecs {
		guids[i] = mustGUID(s.GUID)
	}
	flags, err := QueryAuditSubcategories(guids...)
	if err != nil {
		return nil, err.Error()
	}
	cur := make([]uint32, len(flags))
	for i, f := range flags {
		cur[i] = uint32(f)
	}
	return evaluateDCAudit(cur), ""
}
