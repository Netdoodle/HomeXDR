package syslog

import (
	"strings"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Sophos Firewall (XG, SFOS) sends key=value lines such as
//
//	device_name="SFW" log_type="Firewall" log_component="Firewall Rule" status="Allow"
//	in_interface="Port2" out_interface="Port1" fw_rule_id=3 protocol="TCP"
//	src_ip=192.168.1.10 dst_ip=203.0.113.5 src_port=51234 dst_port=443 sent_bytes=100 recv_bytes=900

func matchSophos(m *Message) bool {
	return strings.Contains(m.Raw, `log_type="Firewall"`) || strings.Contains(m.Raw, "log_type=Firewall")
}

func decodeSophos(m *Message) *event.Event {
	kv := parseKV(m.Raw)
	if !strings.EqualFold(kv["log_type"], "Firewall") {
		return nil
	}
	status := firstNonEmpty(kv["status"], kv["log_subtype"])
	r := fwRecord{
		Vendor: "Sophos", Product: "Sophos Firewall", Dataset: "sophos",
		RawAction: status, Denied: isDeniedAction(status),
		Proto: kv["protocol"], SrcIP: kv["src_ip"], DstIP: kv["dst_ip"],
		SrcPort: atoi(kv["src_port"]), DstPort: atoi(kv["dst_port"]),
		SrcMAC: strings.ToLower(kv["src_mac"]),
		Bytes:  atoi64(kv["sent_bytes"]) + atoi64(kv["recv_bytes"]), Packets: atoi64(kv["sent_pkts"]) + atoi64(kv["recv_pkts"]),
		Interface: kv["in_interface"], Rule: kv["fw_rule_id"],
		Data: map[string]any{
			"rule_name": kv["fw_rule_name"], "application": kv["app_name"], "user": kv["user_name"],
			"dst_interface": kv["out_interface"], "component": kv["log_component"],
		},
	}
	ev := newFirewallEvent(m, r)
	if ev == nil {
		return nil
	}
	ev.Observer.Hostname = firstNonEmpty(kv["device_name"], m.Hostname)
	return ev
}
