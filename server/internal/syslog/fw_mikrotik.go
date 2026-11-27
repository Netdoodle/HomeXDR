package syslog

import (
	"regexp"
	"strings"

	"github.com/Netdoodle/homexdr/shared/event"
)

// MikroTik RouterOS logs a firewall rule with action "log" and a prefix the admin picks:
//
//	forward: in:ether1 out:bridge, src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), 203.0.113.9:40000->192.168.88.10:22, len 60
//
// RouterOS does not record whether the rule accepted or dropped, so the verdict comes
// from the prefix: a word such as drop, block, reject or deny marks it denied.
var mikrotikRe = regexp.MustCompile(`in:(\S*) out:(\S*), (?:src-mac ([0-9A-Fa-f:]{17}), )?proto (\w+)(?: \(([^)]*)\))?, ([0-9a-fA-F.:]+?)(?::(\d+))?->([0-9a-fA-F.:]+?)(?::(\d+))?, (?:NAT [^,]*, )?len (\d+)`)

func matchMikroTik(m *Message) bool {
	return strings.Contains(m.Msg, "->") && strings.Contains(m.Msg, "proto ") && strings.Contains(m.Msg, " in:") && strings.Contains(m.Msg, " out:")
}

func decodeMikroTik(m *Message) *event.Event {
	g := mikrotikRe.FindStringSubmatchIndex(m.Msg)
	if g == nil {
		return nil
	}
	sub := func(i int) string {
		if g[2*i] < 0 {
			return ""
		}
		return m.Msg[g[2*i]:g[2*i+1]]
	}
	prefix := strings.ToLower(m.Msg[:g[0]])
	denied := false
	for _, w := range []string{"drop", "block", "reject", "deny", "denied"} {
		if strings.Contains(prefix, w) {
			denied = true
		}
	}
	verdict := "accept"
	if denied {
		verdict = "drop"
	}
	in := sub(1)
	r := fwRecord{
		Vendor: "MikroTik", Product: "RouterOS", Dataset: "mikrotik",
		RawAction: verdict, Denied: denied,
		Proto: sub(4), SrcIP: sub(6), DstIP: sub(8), SrcPort: atoi(sub(7)), DstPort: atoi(sub(9)),
		SrcMAC: strings.ToLower(sub(3)), Bytes: atoi64(sub(10)), Interface: in,
		Data: map[string]any{"dst_interface": sub(2), "tcp_flags": sub(5), "log_prefix": strings.TrimSpace(m.Msg[:g[0]])},
	}
	return newFirewallEvent(m, r)
}
