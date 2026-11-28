package windows

import "github.com/Netdoodle/homexdr/shared/api"

// This file holds the platform-neutral part of the domain controller audit check: the
// subcategories HomeXDR's directory and Kerberos detections need and the comparison
// with the current policy. The Win32 read lives in dcaudit_windows.go. HomeXDR only
// reports gaps; it never changes audit policy.

// Audit outcome bits, the same values as AuditSuccess and AuditFailure.
const (
	dcAuditSuccess uint32 = 1
	dcAuditFailure uint32 = 2
)

// dcAuditSpec is one required audit subcategory.
type dcAuditSpec struct {
	Name   string
	GUID   string
	Wanted uint32 // dcAuditSuccess, dcAuditFailure or both
}

// dcAuditSpecs are the subcategories a domain controller needs, with the GUIDs
// Microsoft documents for them (auditpol /list /subcategory:* /v).
var dcAuditSpecs = []dcAuditSpec{
	{"Credential Validation", "{0CCE923F-69AE-11D9-BED3-505054503030}", dcAuditSuccess | dcAuditFailure},
	{"Kerberos Authentication Service", "{0CCE9242-69AE-11D9-BED3-505054503030}", dcAuditSuccess | dcAuditFailure},
	{"Kerberos Service Ticket Operations", "{0CCE9240-69AE-11D9-BED3-505054503030}", dcAuditSuccess | dcAuditFailure},
	{"Computer Account Management", "{0CCE9236-69AE-11D9-BED3-505054503030}", dcAuditSuccess},
	{"Security Group Management", "{0CCE9237-69AE-11D9-BED3-505054503030}", dcAuditSuccess},
	{"User Account Management", "{0CCE9235-69AE-11D9-BED3-505054503030}", dcAuditSuccess | dcAuditFailure},
	{"Directory Service Access", "{0CCE923B-69AE-11D9-BED3-505054503030}", dcAuditSuccess},
	{"Directory Service Changes", "{0CCE923C-69AE-11D9-BED3-505054503030}", dcAuditSuccess},
	{"Logon", "{0CCE9215-69AE-11D9-BED3-505054503030}", dcAuditSuccess | dcAuditFailure},
	{"Sensitive Privilege Use", "{0CCE9228-69AE-11D9-BED3-505054503030}", dcAuditSuccess | dcAuditFailure},
}

func dcAuditName(bits uint32) string {
	switch bits & (dcAuditSuccess | dcAuditFailure) {
	case dcAuditSuccess:
		return "success"
	case dcAuditFailure:
		return "failure"
	case dcAuditSuccess | dcAuditFailure:
		return "success and failure"
	}
	return "none"
}

// evaluateDCAudit compares the current setting of each dcAuditSpecs entry (same order,
// as outcome bits) with what is wanted and returns the subcategories that lack some of
// it. current may be shorter than the specs; missing entries count as none.
func evaluateDCAudit(current []uint32) []api.AuditGap {
	var gaps []api.AuditGap
	for i, s := range dcAuditSpecs {
		var cur uint32
		if i < len(current) {
			cur = current[i] & (dcAuditSuccess | dcAuditFailure)
		}
		if cur&s.Wanted == s.Wanted {
			continue
		}
		gaps = append(gaps, api.AuditGap{
			Subcategory: s.Name, GUID: s.GUID, Wanted: dcAuditName(s.Wanted), Current: dcAuditName(cur),
		})
	}
	return gaps
}
