package syslog

import (
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// FortiGate sends key=value lines such as
//
//	date=2026-03-01 time=10:00:00 devname="FGT-A" devid="FGT60F0000000000" logid="0000000013"
//	type="traffic" subtype="forward" level="notice" srcip=192.168.1.10 srcport=51234
//	srcintf="lan" srcintfrole="lan" dstip=203.0.113.5 dstport=443 dstintf="wan1"
//	dstintfrole="wan" proto=6 action="accept" policyid=1 sentbyte=1234 rcvdbyte=5678
//
// The line has no syslog tag, so the header can swallow its first fields; the whole raw
// message is read instead.

func matchFortiGate(m *Message) bool {
	return strings.Contains(m.Raw, "logid=") && strings.Contains(m.Raw, "devid=") &&
		strings.Contains(m.Raw, "type=")
}

func decodeFortiGate(m *Message) *event.Event {
	kv := parseKV(m.Raw)
	if kv["type"] != "traffic" {
		return nil // utm, event and other log types stay plain syslog for now
	}
	r := fwRecord{
		Vendor: "Fortinet", Product: "FortiGate", Dataset: "fortigate",
		RawAction: kv["action"], Denied: isDeniedAction(kv["action"]),
		Proto: kv["proto"], SrcIP: kv["srcip"], DstIP: kv["dstip"],
		SrcPort: atoi(kv["srcport"]), DstPort: atoi(kv["dstport"]),
		SrcMAC: strings.ToLower(kv["srcmac"]),
		Bytes:  atoi64(kv["sentbyte"]) + atoi64(kv["rcvdbyte"]), Packets: atoi64(kv["sentpkt"]) + atoi64(kv["rcvdpkt"]),
		Interface: kv["srcintf"], Rule: kv["policyid"],
		Data: map[string]any{
			"service": kv["service"], "application": kv["app"], "policy_name": kv["policyname"],
			"session_id": kv["sessionid"], "src_role": kv["srcintfrole"], "dst_role": kv["dstintfrole"],
			"dst_interface": kv["dstintf"], "subtype": kv["subtype"], "vdom": kv["vd"], "country": kv["dstcountry"],
		},
	}
	// FortiGate's own idea of the interface role says which way the connection went.
	switch {
	case kv["srcintfrole"] == "wan" && kv["dstintfrole"] != "wan":
		r.Direction = event.DirectionInbound
	case kv["dstintfrole"] == "wan" && kv["srcintfrole"] != "wan":
		r.Direction = event.DirectionOutbound
	}
	ev := newFirewallEvent(m, r)
	if ev == nil {
		return nil
	}
	ev.Observer.Hostname = firstNonEmpty(kv["devname"], m.Hostname)
	if ts := fortiTime(kv); !ts.IsZero() {
		ev.Timestamp = ts
	}
	return ev
}

// fortiTime prefers eventtime (epoch, in seconds, milliseconds or nanoseconds), then the
// date and time fields, which are in the device's own zone and so only a fallback.
func fortiTime(kv map[string]string) time.Time {
	if s := kv["eventtime"]; s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			switch {
			case n > 1e17:
				return time.Unix(0, n).UTC()
			case n > 1e14:
				return time.UnixMicro(n).UTC()
			case n > 1e11:
				return time.UnixMilli(n).UTC()
			default:
				return time.Unix(n, 0).UTC()
			}
		}
	}
	if d, t := kv["date"], kv["time"]; d != "" && t != "" {
		if ts, err := time.ParseInLocation("2006-01-02 15:04:05", d+" "+t, time.Local); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
