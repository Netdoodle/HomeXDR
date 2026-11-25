package darwin

import (
	"net/netip"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// moduleBPF is event.module of the DNS sensor: a BPF capture of port 53 traffic, which
// cannot tell which process sent a query.
const moduleBPF = "bpf"

const (
	// dnsAnswerWait is how long a query waits for its answer before it is reported on
	// its own (dns.type "query"). Most answers arrive within milliseconds; glibc's
	// resolver gives up on a server after 5 s.
	dnsAnswerWait = 5 * time.Second
	// dnsDedupWindow: identical queries (same local address, name and type) within this window
	// are reported once.
	dnsDedupWindow = time.Second
	// dnsMaxFlows bounds the open transactions and the dedup set.
	dnsMaxFlows = 8192
	// dnsSweepEvery is how often unanswered queries are checked.
	dnsSweepEvery = 500 * time.Millisecond
	// dnsMaxEventAnswers caps the answers copied into one event.
	dnsMaxEventAnswers = 32
)

// dnsPacket is one DNS message to or from port 53.
type dnsPacket struct {
	Query         bool // sent to port 53 (otherwise received from port 53)
	TCP           bool // carried over TCP (otherwise UDP)
	Local, Remote netip.AddrPort
	Payload       []byte
	Truncated     bool // only the start of the message was captured
	TS            time.Time
}

// dnsTxKey identifies a DNS transaction: the client's port, the server and the ID. The
// client address is left out because unconnected eBPF sockets do not know it.
type dnsTxKey struct {
	lport uint16
	raddr netip.Addr
	rport uint16
	id    uint16
}

type dnsDedupKey struct {
	local netip.Addr
	name  string
	qtype uint16
}

// dnsFlow is a query (or an answer whose query was not seen) and what was reported.
type dnsFlow struct {
	first         time.Time
	q             dnsQuestion
	local, remote netip.AddrPort
	tcp           bool
	querySeen     bool
	answered      bool
	emitted       bool
}

// dnsTracker pairs queries with answers and emits one event per query: with the answer
// when it arrives, or on its own after the wait. Not safe for concurrent use; the
// sensor's read loop owns it and calls sweep periodically.
type dnsTracker struct {
	module    string
	emit      func(*event.Event)
	wait      time.Duration
	flows     map[dnsTxKey]*dnsFlow    // open transactions; several keys may share a flow
	recent    map[dnsDedupKey]*dnsFlow // flows started within dnsDedupWindow
	lastSweep time.Time
}

func newDNSTracker(module string, emit func(*event.Event)) *dnsTracker {
	return &dnsTracker{module: module, emit: emit, wait: dnsAnswerWait,
		flows: map[dnsTxKey]*dnsFlow{}, recent: map[dnsDedupKey]*dnsFlow{}}
}

func (t *dnsTracker) keyTTL() time.Duration { return max(10*time.Second, 2*t.wait) }

// handle processes one message. Messages that are not DNS, queries that were received
// and answers that were sent (a local DNS server's traffic) are ignored.
func (t *dnsTracker) handle(p dnsPacket) {
	m, err := parseDNS(p.Payload)
	if err == nil && p.Query != m.Response {
		if p.Query {
			t.query(p, m)
		} else {
			t.answer(p, m)
		}
	}
	if p.TS.Sub(t.lastSweep) >= dnsSweepEvery {
		t.sweep(p.TS)
	}
}

func (t *dnsTracker) newFlow(p dnsPacket, q dnsQuestion) *dnsFlow {
	f := &dnsFlow{first: p.TS, q: q, local: p.Local, remote: p.Remote, tcp: p.TCP}
	return f
}

func (t *dnsTracker) query(p dnsPacket, m dnsMessage) {
	q := m.Questions[0]
	k := dnsTxKey{p.Local.Port(), p.Remote.Addr(), p.Remote.Port(), m.ID}
	dk := dnsDedupKey{p.Local.Addr(), q.Name, q.Type}
	if f := t.recent[dk]; f != nil && p.TS.Sub(f.first) < dnsDedupWindow {
		// The same host asked the same question a moment ago (a retry, the other
		// server, another thread): report it once, completed by whichever answer
		// arrives first.
		if _, ok := t.flows[k]; !ok && len(t.flows) < dnsMaxFlows {
			t.flows[k] = f
		}
		return
	}
	f := t.newFlow(p, q)
	f.querySeen = true
	if len(t.flows) >= dnsMaxFlows {
		// Too many open transactions: report the query now rather than track it.
		f.emitted = true
		t.emit(t.event(f, nil, time.Time{}, false))
		return
	}
	if old := t.flows[k]; old != nil && !old.emitted {
		// The transaction key was reused before the old query got an answer.
		old.emitted = true
		t.emit(t.event(old, nil, time.Time{}, false))
	}
	t.flows[k] = f
	if len(t.recent) < dnsMaxFlows {
		t.recent[dk] = f
	}
}

func (t *dnsTracker) answer(p dnsPacket, m dnsMessage) {
	q := m.Questions[0]
	k := dnsTxKey{p.Local.Port(), p.Remote.Addr(), p.Remote.Port(), m.ID}
	if f := t.flows[k]; f != nil && f.q.Name == q.Name && f.q.Type == q.Type {
		if f.answered {
			return // the same answer read twice (MSG_PEEK), or a duplicate
		}
		f.answered = true
		f.emitted = true // if the query was already reported unanswered, this adds the late answer
		t.emit(t.event(f, &m, p.TS, p.Truncated))
		return
	}
	// An answer to a query that was not seen (sent before the sensor started, or not
	// captured): report it.
	dk := dnsDedupKey{p.Local.Addr(), q.Name, q.Type}
	if f := t.recent[dk]; f != nil && p.TS.Sub(f.first) < dnsDedupWindow {
		return
	}
	f := t.newFlow(p, q)
	f.answered, f.emitted = true, true
	if _, taken := t.flows[k]; !taken && len(t.flows) < dnsMaxFlows {
		t.flows[k] = f // absorbs a second read of this answer
	}
	if len(t.recent) < dnsMaxFlows {
		t.recent[dk] = f
	}
	t.emit(t.event(f, &m, p.TS, p.Truncated))
}

// sweep reports queries whose answer did not come in time and forgets old state.
func (t *dnsTracker) sweep(now time.Time) {
	t.lastSweep = now
	ttl := t.keyTTL()
	for k, f := range t.flows {
		age := now.Sub(f.first)
		if !f.emitted && age >= t.wait {
			f.emitted = true
			t.emit(t.event(f, nil, time.Time{}, false))
		}
		if age >= ttl {
			delete(t.flows, k)
		}
	}
	for k, f := range t.recent {
		if now.Sub(f.first) >= dnsDedupWindow {
			delete(t.recent, k)
		}
	}
}

// flush reports every query still waiting for an answer (on shutdown).
func (t *dnsTracker) flush() {
	for _, f := range t.flows {
		if !f.emitted {
			f.emitted = true
			t.emit(t.event(f, nil, time.Time{}, false))
		}
	}
	clear(t.flows)
	clear(t.recent)
}

func dnsEndpoint(ap netip.AddrPort) *event.Endpoint {
	ep := &event.Endpoint{Port: int(ap.Port())}
	if a := ap.Addr(); a.IsValid() && !a.IsUnspecified() {
		ep.IP = a.String()
	}
	return ep
}

// event builds the event for a flow, with the answer if one was seen. The timestamp is
// the query's; event.duration is the time to the answer.
func (t *dnsTracker) event(f *dnsFlow, ans *dnsMessage, at time.Time, ansCut bool) *event.Event {
	d := &event.DNS{Type: "query", Question: event.DNSQuestion{Name: f.q.Name, Type: dnsTypeName(f.q.Type)}}
	typ := "ipv4"
	if f.remote.Addr().Is6() {
		typ = "ipv6"
	}
	transport := "udp"
	if f.tcp {
		transport = "tcp"
	}
	ev := &event.Event{
		Timestamp: f.first,
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryNetwork}, Type: []string{event.TypeProtocol},
			Action: "dns_query", Outcome: event.OutcomeUnknown, Module: t.module, Dataset: "dns",
		},
		Network:     &event.Network{Transport: transport, Type: typ, Protocol: "dns", Direction: event.DirectionOutbound},
		Source:      dnsEndpoint(f.local),
		Destination: dnsEndpoint(f.remote),
		DNS:         d,
	}
	var msg strings.Builder
	msg.WriteString("dns ")
	if ans == nil {
		msg.WriteString("query " + d.Question.Type + " " + d.Question.Name)
	} else {
		d.Type = "answer"
		d.ResponseCode = dnsRCodeName(ans.RCode)
		for _, rr := range ans.Answers {
			if len(d.Answers) < dnsMaxEventAnswers {
				d.Answers = append(d.Answers, event.DNSAnswer{Name: rr.Name, Type: dnsTypeName(rr.Type), Data: rr.Data, TTL: int(rr.TTL)})
			}
			if (rr.Type == dnsTypeA || rr.Type == dnsTypeAAAA) && rr.Data != "" && len(d.ResolvedIP) < dnsMaxEventAnswers {
				d.ResolvedIP = append(d.ResolvedIP, rr.Data)
			}
		}
		if ans.RCode == 0 {
			ev.Event.Outcome = event.OutcomeSuccess
		} else {
			ev.Event.Outcome = event.OutcomeFailure
		}
		if f.querySeen && at.After(f.first) {
			ev.Event.Duration = at.Sub(f.first).Nanoseconds()
		}
		msg.WriteString("answer " + d.Question.Type + " " + d.Question.Name)
		if len(d.ResolvedIP) > 0 {
			msg.WriteString(" -> " + strings.Join(d.ResolvedIP, ", "))
		}
		if ans.RCode != 0 {
			msg.WriteString(" [" + d.ResponseCode + "]")
		}
		if ansCut && ans.Partial {
			// Only the first part of the answer was captured; records are missing.
			ev.Tags = append(ev.Tags, "dns_capture_truncated")
		}
	}
	ev.Message = msg.String()
	return ev
}
