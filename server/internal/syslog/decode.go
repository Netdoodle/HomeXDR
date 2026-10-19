package syslog

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/communityid"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Decode turns a syslog message into an event. kind reports what was recognized:
// "opnsense", "suricata" or "syslog".
func Decode(m *Message) (ev *event.Event, kind string) {
	switch {
	case m.AppName == "filterlog":
		if ev := decodeFilterlog(m); ev != nil {
			return ev, "opnsense"
		}
	case strings.HasPrefix(strings.TrimSpace(m.Msg), "{") && strings.Contains(m.Msg, `"event_type"`):
		if ev := decodeEVE(m); ev != nil {
			return ev, "suricata"
		}
	case m.AppName == "sshd" || strings.HasPrefix(m.AppName, "sshd-"):
		if ev := decodeSSHD(m); ev != nil {
			return ev, "syslog"
		}
	}
	return decodeGeneric(m), "syslog"
}

func base(m *Message, module, dataset string) *event.Event {
	ev := &event.Event{
		ID:        event.NewID(),
		Timestamp: m.Timestamp.UTC(),
		Event:     event.Meta{Kind: event.KindEvent, Module: module, Dataset: dataset},
		Log: &event.Log{
			Level: SeverityName(m.Severity), Facility: FacilityName(m.Facility), AppName: m.AppName,
		},
	}
	return ev
}

func decodeGeneric(m *Message) *event.Event {
	app := strings.ToLower(m.AppName)
	if app == "" {
		app = "unknown"
	}
	ev := base(m, event.ModuleSyslog, "syslog."+sanitizeDataset(app))
	ev.Event.Category = []string{event.CategoryHost}
	ev.Event.Type = []string{event.TypeInfo}
	ev.Message = m.Msg
	ev.Event.Original = truncate(m.Raw, 16<<10)
	if m.ProcID != "" {
		if pid, err := strconv.ParseInt(m.ProcID, 10, 64); err == nil {
			ev.Process = &event.Process{PID: pid, Name: m.AppName}
		}
	}
	if m.Facility == 4 || m.Facility == 10 { // auth, authpriv
		ev.Event.Category = []string{event.CategoryAuthentication}
	}
	return ev
}

var datasetRe = regexp.MustCompile(`[^a-z0-9_.-]+`)

func sanitizeDataset(s string) string { return truncate(datasetRe.ReplaceAllString(s, "_"), 64) }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// filterlog: <rule>,<sub>,<anchor>,<tracker>,<if>,<reason>,<action>,<dir>,<ipver>,...
func decodeFilterlog(m *Message) *event.Event {
	f := strings.Split(strings.TrimSpace(m.Msg), ",")
	if len(f) < 9 {
		return nil
	}
	ev := base(m, event.ModuleOPNsense, "opnsense.filterlog")
	ev.Observer = &event.Observer{Type: "firewall", Vendor: "OPNsense", Product: "OPNsense", Hostname: m.Hostname}
	action := f[6]
	ev.Event.Action = action
	ev.Event.Category = []string{event.CategoryNetwork}
	switch action {
	case "pass":
		ev.Event.Type = []string{event.TypeConnection, event.TypeAllowed}
		ev.Event.Outcome = event.OutcomeSuccess
	default:
		ev.Event.Type = []string{event.TypeConnection, event.TypeDenied}
		ev.Event.Outcome = event.OutcomeFailure
	}
	dir := event.DirectionUnknown
	switch f[7] {
	case "in":
		dir = event.DirectionInbound
	case "out":
		dir = event.DirectionOutbound
	}
	ev.Data = map[string]any{"interface": f[4], "rule_number": f[0], "tracker": f[3], "reason": f[5]}
	ev.Network = &event.Network{Direction: dir}

	var proto, src, dst string
	var length string
	var rest []string
	switch f[8] {
	case "4":
		if len(f) < 20 {
			return nil
		}
		ev.Network.Type = "ipv4"
		proto, length, src, dst = strings.ToLower(f[16]), f[17], f[18], f[19]
		rest = f[20:]
	case "6":
		if len(f) < 17 {
			return nil
		}
		ev.Network.Type = "ipv6"
		proto, length, src, dst = strings.ToLower(f[12]), f[14], f[15], f[16]
		rest = f[17:]
	default:
		return nil
	}
	ev.Network.Transport = proto
	ev.Source = &event.Endpoint{IP: src}
	ev.Destination = &event.Endpoint{IP: dst}
	if n, err := strconv.ParseInt(length, 10, 64); err == nil {
		ev.Network.Bytes = n
	}
	if (proto == "tcp" || proto == "udp") && len(rest) >= 2 {
		ev.Source.Port, _ = strconv.Atoi(rest[0])
		ev.Destination.Port, _ = strconv.Atoi(rest[1])
		if proto == "tcp" && len(rest) >= 4 {
			ev.Data["tcp_flags"] = rest[3]
		}
	}
	ev.Network.CommunityID = communityid.ComputeStrings(src, dst, proto, ev.Source.Port, ev.Destination.Port)
	ev.Message = action + " " + proto + " " + joinHostPort(src, ev.Source.Port) + " -> " +
		joinHostPort(dst, ev.Destination.Port) + " on " + f[4]
	return ev
}

func joinHostPort(ip string, port int) string {
	if port == 0 {
		return ip
	}
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}

type eveRecord struct {
	Timestamp   string `json:"timestamp"`
	FlowID      int64  `json:"flow_id"`
	InIface     string `json:"in_iface"`
	EventType   string `json:"event_type"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Proto       string `json:"proto"`
	AppProto    string `json:"app_proto"`
	CommunityID string `json:"community_id"`
	Host        string `json:"host"`
	Alert       *struct {
		Action      string              `json:"action"`
		SignatureID int64               `json:"signature_id"`
		Rev         int                 `json:"rev"`
		Signature   string              `json:"signature"`
		Category    string              `json:"category"`
		Severity    int                 `json:"severity"`
		Metadata    map[string][]string `json:"metadata"`
	} `json:"alert"`
	DNS *struct {
		Type    string `json:"type"`
		RRName  string `json:"rrname"`
		RRType  string `json:"rrtype"`
		RCode   string `json:"rcode"`
		Queries []struct {
			RRName string `json:"rrname"`
			RRType string `json:"rrtype"`
		} `json:"queries"`
		Answers []struct {
			RRName string `json:"rrname"`
			RRType string `json:"rrtype"`
			TTL    int    `json:"ttl"`
			RData  string `json:"rdata"`
		} `json:"answers"`
	} `json:"dns"`
	HTTP *struct {
		Hostname  string `json:"hostname"`
		URL       string `json:"url"`
		UserAgent string `json:"http_user_agent"`
		Method    string `json:"http_method"`
		Status    int    `json:"status"`
	} `json:"http"`
	TLS *struct {
		SNI     string `json:"sni"`
		Version string `json:"version"`
		Subject string `json:"subject"`
		Issuer  string `json:"issuerdn"`
		JA3     *struct {
			Hash string `json:"hash"`
		} `json:"ja3"`
		JA4 string `json:"ja4"`
	} `json:"tls"`
	Flow *struct {
		PktsToServer  int64  `json:"pkts_toserver"`
		PktsToClient  int64  `json:"pkts_toclient"`
		BytesToServer int64  `json:"bytes_toserver"`
		BytesToClient int64  `json:"bytes_toclient"`
		State         string `json:"state"`
	} `json:"flow"`
}

var eveTimeLayouts = []string{
	"2006-01-02T15:04:05.999999-0700",
	"2006-01-02T15:04:05.999999Z0700",
	time.RFC3339Nano,
}

func decodeEVE(m *Message) *event.Event {
	var r eveRecord
	if json.Unmarshal([]byte(strings.TrimSpace(m.Msg)), &r) != nil || r.EventType == "" {
		return nil
	}
	ev := base(m, event.ModuleSuricata, "suricata."+sanitizeDataset(r.EventType))
	for _, l := range eveTimeLayouts {
		if t, err := time.Parse(l, r.Timestamp); err == nil {
			ev.Timestamp = t.UTC()
			break
		}
	}
	host := r.Host
	if host == "" {
		host = m.Hostname
	}
	ev.Observer = &event.Observer{Type: "ids", Vendor: "OISF", Product: "Suricata", Hostname: host}
	transport := strings.ToLower(r.Proto)
	if transport == "ipv6-icmp" || transport == "icmpv6" {
		transport = "ipv6-icmp"
	}
	ev.Network = &event.Network{Transport: transport, Protocol: strings.ToLower(r.AppProto), CommunityID: r.CommunityID}
	if ev.Network.Protocol == "failed" {
		ev.Network.Protocol = ""
	}
	if r.SrcIP != "" {
		ev.Source = &event.Endpoint{IP: r.SrcIP, Port: r.SrcPort}
	}
	if r.DestIP != "" {
		ev.Destination = &event.Endpoint{IP: r.DestIP, Port: r.DestPort}
	}
	if ev.Network.CommunityID == "" && r.SrcIP != "" && r.DestIP != "" {
		ev.Network.CommunityID = communityid.ComputeStrings(r.SrcIP, r.DestIP, transport, r.SrcPort, r.DestPort)
	}
	ev.Data = map[string]any{"flow_id": r.FlowID, "in_iface": r.InIface}
	ev.Event.Category = []string{event.CategoryNetwork}
	ev.Event.Type = []string{event.TypeProtocol}

	switch r.EventType {
	case "alert":
		if r.Alert == nil {
			return nil
		}
		a := r.Alert
		ev.Event.Kind = event.KindAlert
		ev.Event.Category = []string{event.CategoryIntrusionDetection, event.CategoryNetwork}
		if a.Action == "blocked" {
			ev.Event.Type = []string{event.TypeDenied}
		} else {
			ev.Event.Type = []string{event.TypeAllowed}
		}
		ev.Event.Action = a.Action
		ev.Event.Severity = map[int]int{1: 73, 2: 47, 3: 21}[a.Severity]
		if ev.Event.Severity == 0 {
			ev.Event.Severity = 10
		}
		ev.Rule = &event.Rule{
			ID: strconv.FormatInt(a.SignatureID, 10), Name: a.Signature, Category: a.Category,
			Version: strconv.Itoa(a.Rev), Ruleset: "suricata",
		}
		if ids := a.Metadata["mitre_technique_id"]; len(ids) > 0 {
			ev.Threat = &event.Threat{Framework: "MITRE ATT&CK"}
			for _, id := range ids {
				ev.Threat.Techniques = append(ev.Threat.Techniques, event.MitreItem{ID: id})
			}
		}
		ev.Message = a.Signature
	case "dns":
		if r.DNS == nil {
			break
		}
		d := r.DNS
		name, typ := d.RRName, d.RRType
		if name == "" && len(d.Queries) > 0 {
			name, typ = d.Queries[0].RRName, d.Queries[0].RRType
		}
		dns := &event.DNS{Type: d.Type, Question: event.DNSQuestion{Name: name, Type: typ}, ResponseCode: d.RCode}
		if dns.Type == "request" {
			dns.Type = "query"
		} else if dns.Type == "response" {
			dns.Type = "answer"
		}
		for _, an := range d.Answers {
			dns.Answers = append(dns.Answers, event.DNSAnswer{Name: an.RRName, Type: an.RRType, Data: an.RData, TTL: an.TTL})
			if an.RRType == "A" || an.RRType == "AAAA" {
				dns.ResolvedIP = append(dns.ResolvedIP, an.RData)
			}
		}
		ev.DNS = dns
		ev.Network.Protocol = "dns"
		ev.Message = "dns " + dns.Type + " " + name
	case "http":
		if r.HTTP == nil {
			break
		}
		ev.Event.Category = []string{event.CategoryNetwork, event.CategoryWeb}
		ev.HTTP = &event.HTTP{Method: r.HTTP.Method, URL: r.HTTP.URL, Host: r.HTTP.Hostname,
			UserAgent: r.HTTP.UserAgent, StatusCode: r.HTTP.Status}
		ev.Network.Protocol = "http"
		if ev.Destination != nil {
			ev.Destination.Domain = r.HTTP.Hostname
		}
		ev.Message = r.HTTP.Method + " " + r.HTTP.Hostname + r.HTTP.URL
	case "tls":
		if r.TLS == nil {
			break
		}
		t := &event.TLS{ServerName: r.TLS.SNI, Version: r.TLS.Version, Subject: r.TLS.Subject, Issuer: r.TLS.Issuer, JA4: r.TLS.JA4}
		if r.TLS.JA3 != nil {
			t.JA3 = r.TLS.JA3.Hash
		}
		ev.TLS = t
		ev.Network.Protocol = "tls"
		if ev.Destination != nil {
			ev.Destination.Domain = r.TLS.SNI
		}
		ev.Message = "tls " + r.TLS.SNI
	case "flow":
		ev.Event.Type = []string{event.TypeConnection, event.TypeEnd}
		if r.Flow != nil {
			ev.Network.Bytes = r.Flow.BytesToServer + r.Flow.BytesToClient
			ev.Network.Packets = r.Flow.PktsToServer + r.Flow.PktsToClient
			if ev.Source != nil {
				ev.Source.Bytes, ev.Source.Packets = r.Flow.BytesToServer, r.Flow.PktsToServer
			}
			if ev.Destination != nil {
				ev.Destination.Bytes, ev.Destination.Packets = r.Flow.BytesToClient, r.Flow.PktsToClient
			}
			ev.Data["state"] = r.Flow.State
		}
	default:
		ev.Event.Type = []string{event.TypeInfo}
		ev.Event.Original = truncate(m.Msg, 16<<10)
	}
	return ev
}

var (
	sshFailed   = regexp.MustCompile(`^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	sshAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	sshInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+) port (\d+)`)
)

func decodeSSHD(m *Message) *event.Event {
	msg := strings.TrimSpace(m.Msg)
	var user, ip, port, method, outcome string
	if s := sshFailed.FindStringSubmatch(msg); s != nil {
		method, user, ip, port, outcome = s[1], s[2], s[3], s[4], event.OutcomeFailure
	} else if s := sshAccepted.FindStringSubmatch(msg); s != nil {
		method, user, ip, port, outcome = s[1], s[2], s[3], s[4], event.OutcomeSuccess
	} else if s := sshInvalid.FindStringSubmatch(msg); s != nil {
		user, ip, port, outcome = s[1], s[2], s[3], event.OutcomeFailure
	} else {
		return nil
	}
	ev := base(m, event.ModuleSyslog, "syslog.sshd")
	ev.Event.Category = []string{event.CategoryAuthentication}
	ev.Event.Type = []string{event.TypeStart}
	ev.Event.Outcome = outcome
	ev.Event.Action = "ssh-login"
	if outcome == event.OutcomeFailure {
		ev.Event.Action = "ssh-login-failed"
	}
	ev.User = &event.User{Name: user}
	p, _ := strconv.Atoi(port)
	ev.Source = &event.Endpoint{IP: ip, Port: p}
	ev.Message = msg
	if method != "" {
		ev.Data = map[string]any{"method": method}
	}
	if pid, err := strconv.ParseInt(m.ProcID, 10, 64); err == nil {
		ev.Process = &event.Process{PID: pid, Name: "sshd"}
	}
	return ev
}
