package syslog

import (
	"encoding/csv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Palo Alto PAN-OS sends comma-separated lines whose fourth field is the log type. The
// columns used here are the ones PAN-OS has kept in place across versions 8 to 11:
//
//	1 receive time, 2 serial, 3 type, 4 subtype, 6 generated time, 7 source, 8 destination,
//	11 rule, 12 source user, 14 application, 16 source zone, 17 destination zone,
//	18 inbound interface, 24 source port, 25 destination port, 29 protocol, 30 action,
//	31 bytes, 34 packets (traffic). Threat logs share 7 to 30 and add 32 name, 34 severity.

func matchPaloAlto(m *Message) bool {
	i := strings.Index(m.Msg, ",TRAFFIC,")
	if i < 0 {
		i = strings.Index(m.Msg, ",THREAT,")
	}
	return i >= 0 && i < 80
}

func decodePaloAlto(m *Message) *event.Event {
	rd := csv.NewReader(strings.NewReader(strings.TrimSpace(m.Msg)))
	rd.FieldsPerRecord = -1
	rd.LazyQuotes = true
	f, err := rd.Read()
	if err != nil || len(f) < 31 {
		return nil
	}
	typ := f[3]
	if typ != "TRAFFIC" && typ != "THREAT" {
		return nil
	}
	r := fwRecord{
		Vendor: "Palo Alto Networks", Product: "PAN-OS", Dataset: "paloalto",
		RawAction: f[30], Denied: isDeniedAction(f[30]),
		Proto: f[29], SrcIP: f[7], DstIP: f[8], SrcPort: atoi(f[24]), DstPort: atoi(f[25]),
		Interface: f[18], Rule: f[11],
		Data: map[string]any{
			"application": f[14], "rule_name": f[11], "src_zone": f[16], "dst_zone": f[17],
			"dst_interface": f[19], "log_type": strings.ToLower(typ), "subtype": f[4], "vsys": f[15],
		},
	}
	if f[12] != "" {
		r.Data["user"] = f[12]
	}
	if f[9] != "" && f[9] != "0.0.0.0" {
		r.Data["nat_source_ip"] = f[9]
	}
	if typ == "TRAFFIC" && len(f) > 34 {
		r.Bytes, r.Packets = atoi64(f[31]), atoi64(f[34])
	}
	if typ == "THREAT" && len(f) > 34 {
		r.Data["threat"] = f[32]
		r.Data["severity"] = f[34]
	}
	ev := newFirewallEvent(m, r)
	if ev == nil {
		return nil
	}
	if ts, err := time.ParseInLocation("2006/01/02 15:04:05", f[6], time.Local); err == nil {
		ev.Timestamp = ts.UTC()
	}
	return ev
}
