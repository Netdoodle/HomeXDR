package syslog

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	maxMessage    = 256 << 10
	maxTCPConns   = 256
	tcpIdle       = 10 * time.Minute
	flushInterval = time.Second
	flushSize     = 500
)

// Listener receives syslog and feeds decoded events into the core.
type Listener struct {
	c     *core.Core
	allow []netip.Prefix

	in chan item
}

type item struct {
	src  string
	name string
	kind string
	ev   *event.Event
}

// New returns a listener. allow restricts sources (empty = any).
func New(c *core.Core, allow []netip.Prefix) *Listener {
	return &Listener{c: c, allow: allow, in: make(chan item, 10000)}
}

// Run listens on addr (UDP and TCP) until ctx ends.
func (l *Listener) Run(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return err
	}
	l.c.Syslog.Listening.Store(true)
	l.c.Syslog.Addr.Store(addr)
	l.c.Log.Info("syslog listening", "addr", addr)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); l.batcher(ctx) }()
	go func() { defer wg.Done(); l.serveUDP(ctx, pc) }()
	go func() { defer wg.Done(); l.serveTCP(ctx, ln) }()
	<-ctx.Done()
	pc.Close()
	ln.Close()
	wg.Wait()
	l.c.Syslog.Listening.Store(false)
	return nil
}

func (l *Listener) allowed(ip string) bool {
	if len(l.allow) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range l.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (l *Listener) serveUDP(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, 65536)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ip := hostOf(addr.String())
		if !l.allowed(ip) {
			continue
		}
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			if strings.TrimSpace(line) != "" {
				l.handle(ip, line)
			}
		}
	}
}

func (l *Listener) serveTCP(ctx context.Context, ln net.Listener) {
	sem := make(chan struct{}, maxTCPConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ip := hostOf(conn.RemoteAddr().String())
		if !l.allowed(ip) {
			conn.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			l.readStream(conn, ip)
		}()
	}
}

// readStream handles RFC 6587 octet-counted and newline-delimited framing.
func (l *Listener) readStream(conn net.Conn, ip string) {
	br := bufio.NewReaderSize(conn, 64<<10)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdle))
		b, err := br.Peek(1)
		if err != nil {
			return
		}
		if b[0] >= '1' && b[0] <= '9' {
			lenStr, err := br.ReadString(' ')
			if err != nil {
				return
			}
			n, err := strconv.Atoi(strings.TrimSpace(lenStr))
			if err != nil || n <= 0 || n > maxMessage {
				return
			}
			msg := make([]byte, n)
			if _, err := io.ReadFull(br, msg); err != nil {
				return
			}
			l.handle(ip, string(msg))
			continue
		}
		line, err := readLine(br)
		if err != nil {
			return
		}
		if strings.TrimSpace(line) != "" {
			l.handle(ip, line)
		}
	}
}

func readLine(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		chunk, err := br.ReadSlice('\n')
		sb.Write(chunk)
		if sb.Len() > maxMessage {
			return "", errors.New("message too long")
		}
		if err == nil {
			return sb.String(), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if sb.Len() > 0 && errors.Is(err, io.EOF) {
				return sb.String(), nil
			}
			return "", err
		}
	}
}

func (l *Listener) handle(ip, raw string) {
	st := l.c.Syslog
	st.Received.Add(1)
	m, err := Parse(raw, time.Now())
	if err != nil {
		st.Failed.Add(1)
		return
	}
	ev, kind := Decode(m)
	st.Parsed.Add(1)
	st.Seen(ip, m.Hostname, kind)
	select {
	case l.in <- item{src: ip, name: m.Hostname, kind: kind, ev: ev}:
	default:
		st.Failed.Add(1) // backpressure: drop rather than block the socket
	}
}

func (l *Listener) batcher(ctx context.Context) {
	pending := map[string][]item{}
	count := 0
	tick := time.NewTicker(flushInterval)
	defer tick.Stop()
	flush := func() {
		for src, items := range pending {
			l.flush(context.WithoutCancel(ctx), src, items)
		}
		pending = map[string][]item{}
		count = 0
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case it := <-l.in:
			pending[it.src] = append(pending[it.src], it)
			count++
			if count >= flushSize {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func vendorFor(kind string) string {
	switch kind {
	case "opnsense":
		return "OPNsense"
	case "suricata":
		return "Suricata"
	}
	return ""
}

func (l *Listener) flush(ctx context.Context, src string, items []item) {
	name, vendor := "", ""
	for _, it := range items {
		if it.name != "" {
			name = it.name
		}
		if v := vendorFor(it.kind); v != "" && vendor == "" {
			vendor = v
		}
	}
	host, err := l.c.State.EnsureNetworkHost(ctx, src, name, vendor)
	if err != nil {
		l.c.Log.Error("syslog host", "src", src, "err", err)
		return
	}
	evs := make([]*event.Event, len(items))
	for i, it := range items {
		evs[i] = it.ev
	}
	if err := l.c.Ingest(ctx, host, evs); err != nil {
		l.c.Log.Error("syslog ingest", "src", src, "events", len(evs), "err", err)
		l.c.Syslog.Failed.Add(uint64(len(evs)))
	}
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
