//go:build windows

package windows

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Records from the eventlog sensor keep their EventData verbatim in event.data, under
// the names Windows gives them (TargetUserName, LogonType, ScriptBlockText, ...), so
// Sigma rules written against Windows logs read them without any mapping. Unnamed
// values (classic sources such as the "Windows PowerShell" log) go to data.Data, the
// field Sigma uses for them. data.Channel names the log. A few well-known events also
// get ECS fields (logons, account changes, service installs) for search and the
// server's own detectors.

// channelServices maps channels to the Sigma `service` name for their logs. The
// server's logsource filter matches a service against the dataset suffix, so with
// dataset "windows.<service>" rules for these logs apply without a server-side table.
var channelServices = map[string]string{
	"security":           "security",
	"system":             "system",
	"application":        "application",
	"windows powershell": "powershell-classic",
	"microsoft-windows-powershell/operational":                           "powershell",
	"microsoft-windows-sysmon/operational":                               "sysmon",
	"microsoft-windows-windows defender/operational":                     "windefend",
	"microsoft-windows-taskscheduler/operational":                        "taskscheduler",
	"microsoft-windows-bits-client/operational":                          "bits-client",
	"microsoft-windows-wmi-activity/operational":                         "wmi",
	"microsoft-windows-codeintegrity/operational":                        "codeintegrity-operational",
	"microsoft-windows-windows firewall with advanced security/firewall": "firewall-as",
	"microsoft-windows-dns-client/operational":                           "dns-client",
	"microsoft-windows-ntlm/operational":                                 "ntlm",
	"microsoft-windows-applocker/exe and dll":                            "applocker",
	"microsoft-windows-applocker/msi and script":                         "applocker",
	"microsoft-windows-applocker/packaged app-deployment":                "applocker",
	"microsoft-windows-applocker/packaged app-execution":                 "applocker",
	"openssh/operational":                                                "openssh",
	"microsoft-windows-smbclient/security":                               "smbclient-security",
	"microsoft-windows-terminalservices-localsessionmanager/operational": "terminalservices-localsessionmanager",
	"microsoft-windows-lsa/operational":                                  "lsa-server",
	"microsoft-windows-shell-core/operational":                           "shell-core",
	"microsoft-windows-appxdeploymentserver/operational":                 "appxdeployment-server",
	"microsoft-windows-printservice/admin":                               "printservice-admin",
	"microsoft-windows-printservice/operational":                         "printservice-operational",
	"microsoft-windows-driverframeworks-usermode/operational":            "driver-framework",
	"microsoft-windows-diagnosis-scripted/operational":                   "diagnosis-scripted",
	"microsoft-windows-security-mitigations/kernelmode":                  "security-mitigations",
	"microsoft-windows-security-mitigations/usermode":                    "security-mitigations",
	"microsoft-windows-kernel-shimengine/operational":                    "kernel-shimengine",
	"microsoft-windows-capi2/operational":                                "capi2",
	"microsoft-windows-appmodel-runtime/admin":                           "appmodel-runtime",
}

// eventlogDataset returns "windows.<service>" for a channel.
func eventlogDataset(channel string) string {
	c := strings.ToLower(strings.TrimSpace(channel))
	if s, ok := channelServices[c]; ok {
		return "windows." + s
	}
	var b strings.Builder
	for _, r := range c {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return "windows." + b.String()
}

// knownEvents gives a short description for messages. Keys are "<lowercase channel
// service>/<id>".
var knownEvents = map[string]string{
	"security/1102":                  "audit log cleared",
	"security/4624":                  "logon succeeded",
	"security/4625":                  "logon failed",
	"security/4634":                  "logoff",
	"security/4647":                  "user initiated logoff",
	"security/4648":                  "logon with explicit credentials",
	"security/4672":                  "special privileges assigned to new logon",
	"security/4697":                  "service installed",
	"security/4698":                  "scheduled task created",
	"security/4699":                  "scheduled task deleted",
	"security/4702":                  "scheduled task updated",
	"security/4719":                  "audit policy changed",
	"security/4720":                  "user account created",
	"security/4722":                  "user account enabled",
	"security/4723":                  "password change attempted",
	"security/4724":                  "password reset attempted",
	"security/4725":                  "user account disabled",
	"security/4726":                  "user account deleted",
	"security/4728":                  "member added to a global security group",
	"security/4732":                  "member added to a local security group",
	"security/4729":                  "member removed from a global security group",
	"security/4733":                  "member removed from a local security group",
	"security/4738":                  "user account changed",
	"security/4740":                  "user account locked out",
	"security/4741":                  "computer account created",
	"security/4742":                  "computer account changed",
	"security/4756":                  "member added to a universal security group",
	"security/4757":                  "member removed from a universal security group",
	"security/4662":                  "directory object accessed",
	"security/4673":                  "sensitive privilege used",
	"security/4771":                  "Kerberos pre-authentication failed",
	"security/5136":                  "directory object modified",
	"security/4768":                  "Kerberos TGT requested",
	"security/4769":                  "Kerberos service ticket requested",
	"security/4776":                  "credential validation",
	"system/104":                     "event log cleared",
	"system/7040":                    "service start type changed",
	"system/7045":                    "service installed",
	"powershell/4103":                "PowerShell pipeline execution",
	"powershell/4104":                "PowerShell script block",
	"powershell-classic/400":         "PowerShell engine started",
	"powershell-classic/600":         "PowerShell provider started",
	"powershell-classic/800":         "PowerShell pipeline execution",
	"windefend/1006":                 "Defender found malware",
	"windefend/1116":                 "Defender detected malware",
	"windefend/1117":                 "Defender took action on malware",
	"windefend/1121":                 "Defender ASR rule blocked an action",
	"windefend/1122":                 "Defender ASR rule audited an action",
	"windefend/1123":                 "Defender Controlled Folder Access blocked a write",
	"windefend/1124":                 "Defender Controlled Folder Access audited a write",
	"windefend/1125":                 "Defender Network Protection audited a connection",
	"windefend/1126":                 "Defender Network Protection blocked a connection",
	"windefend/5001":                 "Defender real-time protection disabled",
	"windefend/5007":                 "Defender configuration changed",
	"windefend/5010":                 "Defender scanning for spyware disabled",
	"windefend/5012":                 "Defender scanning for viruses disabled",
	"taskscheduler/106":              "scheduled task registered",
	"taskscheduler/141":              "scheduled task deleted",
	"taskscheduler/200":              "scheduled task action started",
	"wmi/5861":                       "permanent WMI event subscription",
	"bits-client/59":                 "BITS transfer started",
	"codeintegrity-operational/3033": "image blocked by code integrity",
}

// mapEventLogRecord turns a record into an event.
func mapEventLogRecord(r *Record) *event.Event {
	svc := strings.TrimPrefix(eventlogDataset(r.Channel), "windows.")
	code := strconv.FormatUint(uint64(r.EventID), 10)
	data := make(map[string]any, len(r.Data)+4)
	for k, v := range r.Data {
		data[k] = v
	}
	if len(r.Strings) > 0 {
		data["Data"] = append([]string(nil), r.Strings...)
	}
	data["Channel"] = r.Channel
	data["winlog.channel"] = r.Channel
	data["winlog.record_id"] = r.RecordID
	if r.UserSID != "" {
		data["winlog.user_sid"] = r.UserSID
	}
	e := &event.Event{
		Timestamp: recordTime(r),
		Event: event.Meta{
			Kind: event.KindEvent, Module: event.ModuleEventLog, Dataset: "windows." + svc,
			Provider: r.Provider, Code: code,
		},
		Data: data,
	}
	desc := knownEvents[svc+"/"+code]
	if desc == "" {
		desc = r.Channel + " event " + code
	}
	e.Message = desc
	if code == "4" && strings.EqualFold(r.Channel, "OpenSSH/Operational") {
		mapOpenSSH(e, r)
	}
	switch svc {
	case "security":
		mapSecurityRecord(e, r, code)
	case "system":
		if code == "7045" {
			mapServiceInstall(e, r.Data["ServiceName"], r.Data["ImagePath"], r.Data["StartType"], r.Data["AccountName"])
		}
	case "powershell":
		if code == "4104" || code == "4103" {
			if r.ProcessID != 0 {
				e.Process = &event.Process{PID: int64(r.ProcessID)}
			}
		}
	}
	return e
}

// mapSecurityRecord adds ECS fields for logons and account management.
func mapSecurityRecord(e *event.Event, r *Record, code string) {
	d := r.Data
	switch code {
	case "4624", "4625":
		e.Event.Category = []string{event.CategoryAuthentication}
		e.Event.Type = []string{event.TypeStart}
		e.Event.Action = "logon"
		e.Event.Outcome = event.OutcomeSuccess
		if code == "4625" {
			e.Event.Action = "logon_failed"
			e.Event.Outcome = event.OutcomeFailure
		}
		e.User = targetUser(d)
		setSource(e, d["IpAddress"], d["IpPort"], d["WorkstationName"])
		e.Message = logonMessage(e.Message, e.User, d["LogonType"], e.Source)
	case "4634", "4647":
		e.Event.Category = []string{event.CategoryAuthentication}
		e.Event.Type = []string{event.TypeEnd}
		e.Event.Action = "logoff"
		e.Event.Outcome = event.OutcomeSuccess
		e.User = targetUser(d)
		if code == "4647" {
			e.User = subjectUser(d)
		}
	case "4648":
		e.Event.Category = []string{event.CategoryAuthentication}
		e.Event.Type = []string{event.TypeStart}
		e.Event.Action = "explicit_credentials"
		e.User = subjectUser(d)
		if e.User != nil {
			e.User.Target = targetUser(d)
		}
		setSource(e, d["IpAddress"], d["IpPort"], "")
	case "4738":
		e.Event.Category = []string{event.CategoryIAM}
		e.Event.Type = []string{event.TypeChange}
		e.Event.Action = "user_account_changed"
		e.User = subjectUser(d)
		if e.User != nil {
			e.User.Target = targetUser(d)
		}
		mapAccountChange(e, d)
	case "4741", "4742":
		e.Event.Category = []string{event.CategoryIAM}
		e.Event.Type = []string{event.TypeChange}
		e.Event.Action = "computer_account_changed"
		if code == "4741" {
			e.Event.Type = []string{event.TypeCreation}
			e.Event.Action = "computer_account_created"
		}
		e.User = subjectUser(d)
		if e.User != nil {
			e.User.Target = targetUser(d)
		}
		if t := clean(d["TargetUserName"]); t != "" {
			e.Message += ": " + t
		}
	case "4720", "4722", "4723", "4724", "4725", "4726", "4740":
		e.Event.Category = []string{event.CategoryIAM}
		e.Event.Type = []string{iamType(code)}
		e.Event.Action = strings.ReplaceAll(knownEvents["security/"+code], " ", "_")
		e.User = subjectUser(d)
		if e.User != nil {
			e.User.Target = targetUser(d)
		}
	case "4728", "4732", "4756", "4729", "4733", "4757":
		e.Event.Category = []string{event.CategoryIAM}
		e.Event.Type = []string{event.TypeChange}
		e.Event.Action = "group_member_added"
		switch code {
		case "4729", "4733", "4757":
			e.Event.Action = "group_member_removed"
		}
		e.User = subjectUser(d)
		if e.User != nil {
			e.User.Target = &event.User{Name: clean(d["MemberName"]), ID: clean(d["MemberSid"])}
		}
		if g := clean(d["TargetUserName"]); g != "" {
			e.Message += ": " + g
		}
	case "4768", "4769", "4771":
		mapKerberos(e, d, code)
	case "4776":
		e.Event.Category = []string{event.CategoryAuthentication}
		e.Event.Type = []string{event.TypeStart}
		e.Event.Action = "credential_validation"
		e.Event.Outcome = event.OutcomeSuccess
		if st := hexCode(d["Status"]); st != "" && st != "0x0" {
			e.Event.Outcome = event.OutcomeFailure
		}
		e.User = &event.User{Name: clean(d["TargetUserName"])}
		if e.User.Name == "" {
			e.User = nil
		}
		setSource(e, "", "", d["Workstation"])
	case "4662":
		e.Event.Category = []string{event.CategoryIAM}
		e.Event.Type = []string{event.TypeAccess}
		e.Event.Action = "directory_object_accessed"
		e.User = subjectUser(d)
		if hasReplicationRight(d["Properties"]) {
			e.Data[dsReplicationKey] = true
		}
	case "5136":
		e.Event.Category = []string{event.CategoryIAM}
		e.Event.Type = []string{event.TypeChange}
		e.Event.Action = "directory_object_modified"
		e.User = subjectUser(d)
		if dn := clean(d["ObjectDN"]); dn != "" {
			e.Message += ": " + dn
			if a := clean(d["AttributeLDAPDisplayName"]); a != "" {
				e.Message += " (" + a + ")"
			}
		}
	case "4673":
		e.Event.Category = []string{event.CategoryIAM}
		e.Event.Type = []string{event.TypeAdmin}
		e.Event.Action = "sensitive_privilege_used"
		e.User = subjectUser(d)
		if p := clean(d["PrivilegeList"]); p != "" {
			e.Message += ": " + strings.Join(strings.Fields(p), ", ")
		}
	case "4697":
		mapServiceInstall(e, d["ServiceName"], d["ServiceFileName"], d["ServiceStartType"], d["ServiceAccount"])
	}
}

// dsReplicationRights are the extended rights GUIDs that let an account replicate
// directory secrets (DS-Replication-Get-Changes, ...-Get-Changes-All and
// ...-Get-Changes-In-Filtered-Set). Event 4662 lists them in Properties, and a DCSync
// attack shows up as that event from an account that is not a domain controller.
var dsReplicationRights = []string{
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
	"89e95b76-444d-4c62-991a-0facbeda640c",
}

// dsReplicationKey is the data key set on a 4662 event that names a replication right.
const dsReplicationKey = "ds_replication_right"

func hasReplicationRight(properties string) bool {
	p := strings.ToLower(properties)
	for _, g := range dsReplicationRights {
		if strings.Contains(p, g) {
			return true
		}
	}
	return false
}

// accountChangeAttrs are the 4738 fields that hold a value only when the change touched
// them (Windows writes "-" for the rest).
var accountChangeAttrs = []string{
	"SamAccountName", "DisplayName", "UserPrincipalName", "HomeDirectory", "HomePath",
	"ScriptPath", "ProfilePath", "UserWorkstations", "PasswordLastSet", "AccountExpires",
	"PrimaryGroupId", "AllowedToDelegateTo", "UserAccountControl", "UserParameters",
	"SidHistory", "LogonHours",
}

// mapAccountChange names the attributes a 4738 changed in the message.
func mapAccountChange(e *event.Event, d map[string]string) {
	var changed []string
	for _, a := range accountChangeAttrs {
		if v := clean(d[a]); v != "" && v != "<value not set>" {
			changed = append(changed, a)
		}
	}
	if t := targetUser(d); t != nil && t.Name != "" {
		e.Message += ": "
		if t.Domain != "" {
			e.Message += t.Domain + `\`
		}
		e.Message += t.Name
	}
	if len(changed) > 0 {
		e.Message += " (changed: " + strings.Join(changed, ", ") + ")"
	}
}

func firstNonEmpty(a, b string) string {
	if clean(a) != "" {
		return a
	}
	return b
}

// encryptionTypes names Kerberos encryption types (RFC 3961, RFC 4757).
var encryptionTypes = map[string]string{
	"0x1": "des-cbc-crc", "0x3": "des-cbc-md5", "0x11": "aes128-cts-hmac-sha1-96",
	"0x12": "aes256-cts-hmac-sha1-96", "0x17": "rc4-hmac", "0x18": "rc4-hmac-exp",
}

// hexCode normalizes a code Windows prints as "0x17" (or "0X17") to lowercase hex; "-"
// becomes empty and any other value is returned trimmed and lowercased.
func hexCode(s string) string {
	s = clean(s)
	if strings.HasPrefix(s, "0X") {
		s = "0x" + s[2:]
	}
	return strings.ToLower(s)
}

// mapKerberos fills the authentication fields and event.kerberos of 4768, 4769 and 4771.
func mapKerberos(e *event.Event, d map[string]string, code string) {
	e.Event.Category = []string{event.CategoryAuthentication}
	e.Event.Type = []string{event.TypeStart}
	e.Event.Outcome = event.OutcomeSuccess
	switch code {
	case "4768":
		e.Event.Action = "kerberos_tgt_request"
	case "4769":
		e.Event.Action = "kerberos_service_ticket"
	case "4771":
		e.Event.Action = "kerberos_preauth_failed"
		e.Event.Outcome = event.OutcomeFailure
	}
	k := &event.Kerberos{
		ServiceName:          clean(d["ServiceName"]),
		TicketEncryptionType: hexCode(d["TicketEncryptionType"]),
		Status:               hexCode(d["Status"]),
		TicketOptions:        hexCode(d["TicketOptions"]),
		PreAuthType:          clean(d["PreAuthType"]),
	}
	if k.Status == "" && code != "4771" {
		k.Status = hexCode(d["FailureCode"])
	}
	if k.Status != "" && k.Status != "0x0" {
		e.Event.Outcome = event.OutcomeFailure
	}
	k.Encryption = encryptionTypes[k.TicketEncryptionType]
	e.Kerberos = k
	// Kerberos events name the account's SID TargetSid, not TargetUserSid.
	e.User = accountFields(d["TargetUserName"], d["TargetDomainName"], firstNonEmpty(d["TargetUserSid"], d["TargetSid"]))
	setSource(e, d["IpAddress"], d["IpPort"], "")
	if e.User != nil && e.User.Name != "" {
		e.Message += ": " + e.User.Name
		if k.ServiceName != "" && code == "4769" {
			e.Message += " -> " + k.ServiceName
		}
		if k.Encryption != "" {
			e.Message += " (" + k.Encryption + ")"
		}
	}
}

func iamType(code string) string {
	switch code {
	case "4720":
		return event.TypeCreation
	case "4726":
		return event.TypeDeletion
	}
	return event.TypeChange
}

func mapServiceInstall(e *event.Event, name, path, start, account string) {
	e.Event.Category = []string{event.CategoryConfiguration}
	e.Event.Type = []string{event.TypeCreation}
	e.Event.Action = "service_installed"
	e.Service = &event.Service{Name: clean(name), Path: clean(path), StartType: serviceStart(start), Account: clean(account)}
	if e.Service.Name != "" {
		e.Message = "service installed: " + e.Service.Name
		if e.Service.Path != "" {
			e.Message += " (" + e.Service.Path + ")"
		}
	}
}

// serviceStart normalizes 7045's text ("auto start") and 4697's number (2).
func serviceStart(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "boot start":
		return "boot"
	case "1", "system start":
		return "system"
	case "2", "auto start":
		return "auto"
	case "3", "demand start":
		return "manual"
	case "4", "disabled":
		return "disabled"
	}
	return ""
}

func targetUser(d map[string]string) *event.User {
	return accountFields(d["TargetUserName"], d["TargetDomainName"], d["TargetUserSid"])
}

func subjectUser(d map[string]string) *event.User {
	return accountFields(d["SubjectUserName"], d["SubjectDomainName"], d["SubjectUserSid"])
}

func accountFields(name, domain, sid string) *event.User {
	name, domain, sid = clean(name), clean(domain), clean(sid)
	if sid == "S-1-0-0" {
		sid = ""
	}
	if name == "" && sid == "" {
		return nil
	}
	return &event.User{Name: name, Domain: domain, ID: sid}
}

// setSource fills source.ip/port from a logon event; "-", empty and loopback addresses
// (local logons) are left out, but the workstation name is kept as source.domain.
func setSource(e *event.Event, ip, port, workstation string) {
	ip, workstation = clean(ip), clean(workstation)
	src := &event.Endpoint{}
	if a, err := netip.ParseAddr(ip); err == nil && !a.IsLoopback() && !a.IsUnspecified() {
		src.IP = a.Unmap().String()
		if p, err := strconv.Atoi(clean(port)); err == nil && p > 0 {
			src.Port = p
		}
	}
	if workstation != "" {
		src.Domain = workstation
	}
	if src.IP != "" || src.Domain != "" {
		e.Source = src
	}
}

// logonTypes names LogonType values for messages.
var logonTypes = map[string]string{
	"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
	"8": "network cleartext", "9": "new credentials", "10": "remote interactive", "11": "cached interactive",
}

func logonMessage(desc string, u *event.User, logonType string, src *event.Endpoint) string {
	var b strings.Builder
	b.WriteString(desc)
	if u != nil && u.Name != "" {
		b.WriteString(": ")
		if u.Domain != "" {
			b.WriteString(u.Domain + `\`)
		}
		b.WriteString(u.Name)
	}
	if t := logonTypes[strings.TrimSpace(logonType)]; t != "" {
		b.WriteString(" (" + t)
		if src != nil && src.IP != "" {
			b.WriteString(" from " + src.IP)
		}
		b.WriteString(")")
	}
	return b.String()
}
