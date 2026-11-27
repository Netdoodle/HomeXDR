package syslog

import (
	"regexp"
	"strings"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Ubiquiti UniFi gateways (UniFi OS, USG, UDM, UCG) and EdgeRouters (EdgeOS) log firewall
// hits through Linux netfilter, with the rule name in brackets in front of the packet:
//
//	[WAN_IN-3000-D]IN=eth0 OUT=eth1 MAC=... SRC=203.0.113.9 DST=192.168.1.10 LEN=40 PROTO=TCP SPT=40000 DPT=23 SYN
//
// The last letter of the rule name is the verdict: A accept, D drop, R reject. Turn on
// logging for the rule (UniFi: Settings > Policy Table, "Syslog"; EdgeOS: "log enable")
// and point remote syslog at HomeXDR. Lines of the same shape without that rule name
// pattern (OpenWrt, plain iptables) are still read, as a generic Linux firewall.
var (
	ubiRuleRe = regexp.MustCompile(`\[([A-Za-z0-9_.]+(?:-[A-Za-z0-9_]+)*)-([ADR])\]`)
	nfKeyRe   = regexp.MustCompile(`\b(IN|OUT|MAC|SRC|DST|LEN|PROTO|SPT|DPT|TYPE|CODE)=(\S*)`)
)

func matchUbiquiti(m *Message) bool {
	return strings.Contains(m.Msg, "SRC=") && strings.Contains(m.Msg, "DST=") && strings.Contains(m.Msg, "PROTO=")
}

func decodeUbiquiti(m *Message) *event.Event {
	f := map[string]string{}
	for _, g := range nfKeyRe.FindAllStringSubmatch(m.Msg, -1) {
		if _, ok := f[g[1]]; !ok {
			f[g[1]] = g[2]
		}
	}
	rule, verdict := "", ""
	if g := ubiRuleRe.FindStringSubmatch(m.Msg); g != nil {
		rule, verdict = g[1], g[2]
	}
	r := fwRecord{
		Vendor: "Ubiquiti", Product: "UniFi / EdgeOS", Dataset: "ubiquiti",
		Proto: f["PROTO"], SrcIP: f["SRC"], DstIP: f["DST"], SrcPort: atoi(f["SPT"]), DstPort: atoi(f["DPT"]),
		Bytes: atoi64(f["LEN"]), Interface: f["IN"], Rule: rule,
		Data: map[string]any{"dst_interface": f["OUT"]},
	}
	if rule == "" { // not a Ubiquiti rule name: a generic Linux firewall line
		r.Vendor, r.Product, r.Dataset = "Linux", "netfilter", "netfilter"
		// Without the A/D/R suffix the verdict is unknown. A log prefix is the only hint.
		verdict = ""
		low := strings.ToLower(m.Msg)
		if strings.Contains(low, "drop") || strings.Contains(low, "block") || strings.Contains(low, "reject") || strings.Contains(low, "deny") {
			verdict = "D"
		}
	}
	switch verdict {
	case "D", "R":
		r.Denied = true
		r.RawAction = map[string]string{"D": "drop", "R": "reject"}[verdict]
	case "A":
		r.RawAction = "accept"
	}
	if mac := f["MAC"]; len(mac) >= 36 { // dst mac, src mac, ethertype
		r.SrcMAC = strings.ToLower(mac[18:35])
	}
	return newFirewallEvent(m, r)
}
