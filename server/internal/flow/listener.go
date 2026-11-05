package flow

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/netscope"
	"github.com/Netdoodle/homexdr/shared/communityid"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	queueSize     = 4096 // packets waiting to be decoded; more are dropped and counted
	flushInterval = 2 * time.Second
	flushSize     = 1000
)

// Listener receives flow packets and feeds their records into the core as events.
type Listener struct {
	c     *core.Core
	allow []netip.Prefix
	dec   *Decoder
	in    chan packet
}

type packet struct {
	src  netip.Addr
	data []byte
}

// New returns a listener. allow restricts exporters (empty = any).
func New(c *core.Core, allow []netip.Prefix) *Listener {
	return &Listener{c: c, allow: allow, dec: NewDecoder(), in: make(chan packet, queueSize)}
}

// Run listens on addr until ctx ends.
func (l *Listener) Run(ctx context.Context, addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	_ = conn.SetReadBuffer(4 << 20)
	st := l.c.Flow
	st.Listening.Store(true)
	st.Addr.Store(addr)
	l.c.Log.Info("netflow listening", "addr", addr)
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.batcher(ctx)
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	buf := make([]byte, 65536)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			continue
		}
		src := from.Addr().Unmap()
		if !l.allowed(src) {
			st.Refused.Add(1)
			continue
		}
		st.Packets.Add(1)
		select {
		case l.in <- packet{src: src, data: append([]byte(nil), buf[:n]...)}:
		default:
			st.Dropped.Add(1) // backpressure: drop rather than fall behind the socket
		}
	}
	<-done
	st.Listening.Store(false)
	return nil
}

func (l *Listener) allowed(a netip.Addr) bool {
	if len(l.allow) == 0 {
		return true
	}
	for _, p := range l.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// batcher decodes packets and inserts their records in batches. Inserting here means a
// slow event store fills the queue, which then drops packets instead of using more memory.
func (l *Listener) batcher(ctx context.Context) {
	pending := map[string][]*event.Event{}
	count := 0
	tick := time.NewTicker(flushInterval)
	defer tick.Stop()
	flush := func() {
		for src, evs := range pending {
			l.flush(context.WithoutCancel(ctx), src, evs)
		}
		pending, count = map[string][]*event.Event{}, 0
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case p := <-l.in:
			src := p.src.String()
			now := time.Now().UTC()
			res, err := l.dec.Decode(src, p.data, now)
			st := l.c.Flow
			if err != nil {
				st.Malformed.Add(1)
			}
			st.Waiting.Add(uint64(res.Waiting))
			st.Discarded.Add(uint64(res.Discarded))
			st.Records.Add(uint64(len(res.Records)))
			version := 0
			if len(p.data) >= 2 {
				version = int(p.data[0])<<8 | int(p.data[1])
			}
			st.Seen(src, version, len(res.Records), l.dec.Templates(src), now)
			for i := range res.Records {
				pending[src] = append(pending[src], recordEvent(&res.Records[i], now))
			}
			count += len(res.Records)
			if count >= flushSize {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (l *Listener) flush(ctx context.Context, src string, evs []*event.Event) {
	if len(evs) == 0 {
		return
	}
	// The same host as this address's syslog, when it sends both: one device.
	host, err := l.c.State.EnsureNetworkHost(ctx, src, "", "")
	if err != nil {
		l.c.Log.Error("netflow host", "src", src, "err", err)
		l.c.Flow.Failed.Add(uint64(len(evs)))
		return
	}
	if err := l.c.Ingest(ctx, host, evs); err != nil {
		l.c.Log.Error("netflow ingest", "src", src, "events", len(evs), "err", err)
		l.c.Flow.Failed.Add(uint64(len(evs)))
	}
}

var transports = map[uint8]string{
	1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah", 58: "ipv6-icmp", 132: "sctp",
}

func transportName(proto uint8) string {
	if s, ok := transports[proto]; ok {
		return s
	}
	return strconv.Itoa(int(proto))
}

// recordEvent turns a flow record into an event. Its time is when the flow started, so
// the gaps between a device's connections stay measurable.
func recordEvent(r *Record, now time.Time) *event.Event {
	ts := r.Start
	if ts.IsZero() {
		ts = now
	}
	src, dst := r.Src.String(), r.Dst.String()
	transport := transportName(r.Proto)
	netType := "ipv4"
	if r.Src.Is6() {
		netType = "ipv6"
	}
	ev := &event.Event{
		ID:        event.NewID(),
		Timestamp: ts,
		Event: event.Meta{
			Kind: event.KindEvent, Module: event.ModuleNetFlow, Dataset: "netflow.flow",
			Category: []string{event.CategoryNetwork}, Type: []string{event.TypeConnection},
			Action: "flow",
		},
		Source:      &event.Endpoint{IP: src, Port: int(r.SrcPort), Bytes: int64(r.Bytes), Packets: int64(r.Packets)},
		Destination: &event.Endpoint{IP: dst, Port: int(r.DstPort)},
		Network: &event.Network{
			Transport: transport, Type: netType, Direction: netscope.Direction(r.Src, r.Dst),
			Bytes: int64(r.Bytes), Packets: int64(r.Packets),
			CommunityID: communityid.ComputeStrings(src, dst, transport, int(r.SrcPort), int(r.DstPort)),
		},
		Observer: &event.Observer{Type: "netflow"},
		Data:     map[string]any{"flow_version": r.Version},
	}
	if !r.Start.IsZero() {
		ev.Data["flow_start"] = r.Start.Format(time.RFC3339Nano)
	}
	if !r.End.IsZero() {
		ev.Data["flow_end"] = r.End.Format(time.RFC3339Nano)
		if !r.Start.IsZero() && r.End.After(r.Start) {
			ev.Event.Duration = r.End.Sub(r.Start).Nanoseconds()
		}
	}
	if r.InIf != 0 {
		ev.Data["in_interface"] = r.InIf
	}
	if r.OutIf != 0 {
		ev.Data["out_interface"] = r.OutIf
	}
	if r.Proto == 6 && r.TCPFlags != 0 {
		ev.Data["tcp_flags"] = tcpFlags(r.TCPFlags)
	}
	ev.Message = transport + " " + hostPort(src, r.SrcPort) + " -> " + hostPort(dst, r.DstPort) + " " +
		strconv.FormatUint(r.Bytes, 10) + " bytes"
	return ev
}

func hostPort(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

func tcpFlags(f uint8) string {
	out := make([]byte, 0, 8)
	for i, c := range []byte("FSRPAUEC") {
		if f&(1<<i) != 0 {
			out = append(out, c)
		}
	}
	return string(out)
}
