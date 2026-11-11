package adguard

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// Dataset is event.dataset of AdGuard Home lookups.
const Dataset = "dns.adguard"

// Entry is one lookup in AdGuard Home's query log (GET /control/querylog).
type Entry struct {
	Answer []struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
		TTL   int             `json:"ttl"`
	} `json:"answer"`
	Cached     bool   `json:"cached"`
	Client     string `json:"client"`
	ClientInfo *struct {
		Name string `json:"name"`
	} `json:"client_info"`
	ClientProto string          `json:"client_proto"`
	Elapsed     json.RawMessage `json:"elapsedMs"`
	Question    struct {
		Class string `json:"class"`
		Name  string `json:"name"`
		Type  string `json:"type"`
	} `json:"question"`
	Reason string `json:"reason"`
	Rules  []struct {
		Text string `json:"text"`
	} `json:"rules"`
	ServiceName string `json:"service_name"`
	Status      string `json:"status"`
	Time        string `json:"time"`
	Upstream    string `json:"upstream"`

	// kind is the resolver the entry came from (empty: AdGuard Home), and block whether
	// it blocked the lookup, for resolvers other than AdGuard Home.
	kind  string
	block bool
}

// When parses the entry's time.
func (e *Entry) When() (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, e.Time)
	return t, err == nil
}

// key identifies an entry among those logged at the same instant.
func (e *Entry) key() string {
	return e.Time + "|" + e.Client + "|" + e.Question.Name + "|" + e.Question.Type + "|" + e.Status
}

// Blocked reports whether AdGuard Home filtered the lookup rather than answering it.
func (e *Entry) Blocked() bool {
	if normalKind(e.kind) != KindAdGuard {
		return e.block
	}
	return strings.HasPrefix(e.Reason, "Filtered")
}

// observer names the resolver on the event.
func observer(kind string) *event.Observer {
	switch normalKind(kind) {
	case KindPiHole:
		return &event.Observer{Type: "dns", Vendor: "Pi-hole", Product: "Pi-hole"}
	case KindTechnitium:
		return &event.Observer{Type: "dns", Vendor: "Technitium", Product: "Technitium DNS Server"}
	}
	return &event.Observer{Type: "dns", Vendor: "AdGuard", Product: "AdGuard Home"}
}

// Event turns an entry into a DNS event. Every resolver's lookups get the same shape; only
// the dataset, the observer and the key under data (data.adguard, data.pihole, ...) differ. It returns nil for entries without a client address
// or a name, which say nothing about a device.
func (e *Entry) Event() *event.Event {
	at, ok := e.When()
	if !ok {
		return nil
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(e.Client))
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(e.Question.Name), "."))
	if name == "" {
		return nil
	}
	qtype := strings.ToUpper(e.Question.Type)
	netType := "ipv4"
	if addr.Is6() {
		netType = "ipv6"
	}
	ev := &event.Event{
		ID:        event.NewID(),
		Timestamp: at.UTC(),
		Event: event.Meta{
			Kind: event.KindEvent, Module: event.ModuleDNS, Dataset: DatasetFor(e.kind),
			Category: []string{event.CategoryNetwork}, Type: []string{event.TypeProtocol},
			Action: "dns-answer", Outcome: event.OutcomeSuccess,
		},
		Observer: observer(e.kind),
		Source:   &event.Endpoint{IP: addr.String()},
		Network:  &event.Network{Protocol: "dns", Type: netType},
		DNS: &event.DNS{
			Type: "answer", Question: event.DNSQuestion{Name: name, Type: qtype},
			ResponseCode: strings.ToUpper(e.Status),
		},
	}
	for _, a := range e.Answer {
		v := answerValue(a.Value)
		if v == "" {
			continue
		}
		if len(ev.DNS.Answers) < 16 {
			ev.DNS.Answers = append(ev.DNS.Answers, event.DNSAnswer{Name: name, Type: strings.ToUpper(a.Type), Data: v, TTL: a.TTL})
		}
		if t := strings.ToUpper(a.Type); (t == "A" || t == "AAAA") && len(ev.DNS.ResolvedIP) < 16 {
			if ip, err := netip.ParseAddr(v); err == nil {
				ev.DNS.ResolvedIP = append(ev.DNS.ResolvedIP, ip.Unmap().String())
			}
		}
	}
	data := map[string]any{"reason": e.Reason, "cached": e.Cached}
	if e.Upstream != "" {
		data["upstream"] = e.Upstream
	}
	if e.ClientProto != "" {
		data["client_proto"] = e.ClientProto
	}
	if e.ClientInfo != nil && e.ClientInfo.Name != "" {
		data["client_name"] = e.ClientInfo.Name
	}
	if e.ServiceName != "" {
		data["blocked_service"] = e.ServiceName
	}
	if ms, ok := elapsedMs(e.Elapsed); ok && ms >= 0 {
		data["response_time_ms"] = ms
	}
	var rules []string
	for _, r := range e.Rules {
		if r.Text != "" && len(rules) < 3 {
			rules = append(rules, r.Text)
		}
	}
	if len(rules) > 0 {
		data["rules"] = rules
	}
	ev.Data = map[string]any{normalKind(e.kind): data}
	verb := "answer " + ev.DNS.ResponseCode
	if e.Blocked() {
		ev.Event.Action = "dns-blocked"
		ev.Event.Outcome = event.OutcomeFailure
		verb = "blocked (" + e.Reason + ")"
	}
	ev.Message = "dns " + verb + " " + name + " " + qtype + " for " + ev.Source.IP
	return ev
}

// answerValue reads an answer's value, which AdGuard Home writes as a string for most
// types and as an object for a few (SOA, SVCB).
func answerValue(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	if len(raw) > 0 && len(raw) <= 512 {
		return string(raw)
	}
	return ""
}

// elapsedMs reads elapsedMs, a string in AdGuard Home's API ("0.43") and a number in some
// versions.
func elapsedMs(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		f, err := strconv.ParseFloat(s, 64)
		return f, err == nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return f, true
	}
	return 0, false
}
