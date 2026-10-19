//go:build linux

package linux

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// moduleAFPacket is event.module of the DNS sensor's packet-capture fallback (an
// AF_PACKET socket, no process attribution).
const moduleAFPacket = "afpacket"

const (
	// dnsAnswerWait is how long a query waits for its answer before it is reported on
	// its own (dns.type "query"). Most answers arrive within milliseconds; glibc's
	// resolver gives up on a server after 5 s.
	dnsAnswerWait = 5 * time.Second
	// dnsDedupWindow: identical queries (same process, name and type) within this window
	// are reported once.
	dnsDedupWindow = time.Second
	// dnsMaxFlows bounds the open transactions and the dedup set.
	dnsMaxFlows = 8192
	// dnsSweepEvery is how often unanswered queries are checked.
	dnsSweepEvery = 500 * time.Millisecond
	// dnsMaxEventAnswers caps the answers copied into one event.
	dnsMaxEventAnswers = 32
)

// dnsSensor reports DNS queries over UDP port 53 with the issuing process and, when
// seen, the answer. Implementations, best first: eBPF on the UDP send and receive paths
// (process attribution, all network namespaces), then an AF_PACKET capture in the
// agent's network namespace without process attribution (reported as degraded).
type dnsSensor struct {
	sensorState
	env   platform.Env
	self  uint32
	wait  time.Duration
	procs *lru[string, dnsProcInfo] // entity ID -> what /proc said about it
	// The implementations' setup, replaceable in tests.
	loadBPF    func() (*dnsBPF, error)
	openPacket func() (*os.File, error)
}

type dnsProcInfo struct {
	exe, cmdline, name string
}

func newDNSSensor(env platform.Env) *dnsSensor {
	return &dnsSensor{sensorState: sensorState{name: "dns"}, env: env, self: uint32(os.Getpid()),
		wait: dnsAnswerWait, procs: newLRU[string, dnsProcInfo](8192),
		loadBPF: loadDNSBPF, openPacket: openDNSPacketSocket}
}

// Name returns "dns".
func (s *dnsSensor) Name() string { return "dns" }

// Run uses eBPF, falling back to packet capture.
func (s *dnsSensor) Run(ctx context.Context, out platform.Emitter) error {
	out = countingEmitter{s: &s.sensorState, out: out}
	s.set(event.ModuleEBPF, api.SensorRunning, "")
	err := s.runEBPF(ctx, out)
	if err == nil || !isUnavailable(err) {
		return err
	}
	reason := "eBPF unavailable: " + err.Error()
	s.env.Log.Warn("dns sensor: eBPF unavailable, capturing DNS packets without process attribution", "err", err)
	s.set(moduleAFPacket, api.SensorDegraded, reason+"; packet capture without process attribution")
	err2 := s.runPacket(ctx, out)
	if err2 == nil || !isUnavailable(err2) {
		return err2
	}
	msg := reason + "; packet capture unavailable: " + err2.Error()
	s.set(moduleAFPacket, api.SensorFailed, msg)
	return errors.New(msg)
}

// newTracker returns a tracker emitting into out with this sensor's settings.
func (s *dnsSensor) newTracker(module string, out platform.Emitter) *dnsTracker {
	t := newDNSTracker(module, out.Emit)
	t.wait = s.wait
	t.resolve = s.process
	return t
}

// process describes the process of an eBPF record. /proc is read once per process
// (entity) and cached, so this must run when the record arrives, while a short-lived
// resolver client such as getent may still exist.
func (s *dnsSensor) process(p *dnsProc) *event.Process {
	pid := int64(p.PID)
	key := StartKeyFromNS(p.StartNS)
	entity := s.env.EntityID(pid, key)
	info := s.procInfo(entity, pid, key)
	proc := &event.Process{
		EntityID: entity, PID: pid, Name: p.Comm, Executable: info.exe, CommandLine: info.cmdline,
		User: &event.User{ID: strconv.FormatUint(uint64(p.UID), 10), Name: users.name(p.UID)},
	}
	if info.name != "" {
		proc.Name = info.name
	}
	if p.PPID > 0 {
		ppid := int64(p.PPID)
		pkey := StartKeyFromNS(p.ParentNS)
		pe := s.env.EntityID(ppid, pkey)
		pi := s.procInfo(pe, ppid, pkey)
		proc.Parent = &event.Process{EntityID: pe, PID: ppid, Name: pi.name, Executable: pi.exe, CommandLine: pi.cmdline}
	}
	return proc
}

// procInfo reads a process's executable and command line from /proc, if the PID still
// belongs to the process that started at key (not a successor that reused the PID).
func (s *dnsSensor) procInfo(entity string, pid int64, key uint64) dnsProcInfo {
	if info, ok := s.procs.get(entity); ok {
		return info
	}
	var info dnsProcInfo
	st, err := readStat(pid)
	if err != nil || st.StartTick != key {
		return info
	}
	info.name = st.Comm
	info.exe = readLink(pid, "exe")
	if args := readCmdline(pid); len(args) > 0 {
		info.cmdline = joinArgs(args)
	}
	if info.exe != "" {
		info.name = filepath.Base(info.exe)
	}
	s.procs.put(entity, info)
	return info
}

// dnsProc is the process of an eBPF record.
type dnsProc struct {
	PID, TID, PPID, UID uint32
	StartNS, ParentNS   uint64
	Comm                string
}

// dnsPacket is one DNS message to or from port 53, from either implementation.
type dnsPacket struct {
	Query         bool // sent to port 53 (otherwise received from port 53)
	Local, Remote netip.AddrPort
	Payload       []byte
	Truncated     bool     // only the start of the message was captured
	Proc          *dnsProc // nil without process attribution
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
	pid   uint32
	name  string
	qtype uint16
}

// dnsFlow is a query (or an answer whose query was not seen) and what was reported.
type dnsFlow struct {
	first         time.Time
	q             dnsQuestion
	local, remote netip.AddrPort
	proc          *event.Process
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
	resolve   func(*dnsProc) *event.Process
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

func pidOf(p dnsPacket) uint32 {
	if p.Proc != nil {
		return p.Proc.PID
	}
	return 0
}

func (t *dnsTracker) newFlow(p dnsPacket, q dnsQuestion) *dnsFlow {
	f := &dnsFlow{first: p.TS, q: q, local: p.Local, remote: p.Remote}
	if p.Proc != nil && t.resolve != nil {
		f.proc = t.resolve(p.Proc)
	}
	return f
}

func (t *dnsTracker) query(p dnsPacket, m dnsMessage) {
	q := m.Questions[0]
	k := dnsTxKey{p.Local.Port(), p.Remote.Addr(), p.Remote.Port(), m.ID}
	dk := dnsDedupKey{pidOf(p), q.Name, q.Type}
	if f := t.recent[dk]; f != nil && p.TS.Sub(f.first) < dnsDedupWindow {
		// The same process asked the same question a moment ago (a retry, the other
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
	// captured): report it with the receiving process.
	dk := dnsDedupKey{pidOf(p), q.Name, q.Type}
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
	ev := &event.Event{
		Timestamp: f.first,
		Event: event.Meta{
			Kind: event.KindEvent, Category: []string{event.CategoryNetwork}, Type: []string{event.TypeProtocol},
			Action: "dns_query", Outcome: event.OutcomeUnknown, Module: t.module, Dataset: "dns",
		},
		Network:     &event.Network{Transport: "udp", Type: typ, Protocol: "dns", Direction: event.DirectionOutbound},
		Source:      dnsEndpoint(f.local),
		Destination: dnsEndpoint(f.remote),
		DNS:         d,
		Process:     f.proc,
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
	if f.proc != nil && f.proc.Name != "" {
		msg.WriteString(" (" + f.proc.Name + ")")
	}
	ev.Message = msg.String()
	return ev
}
