package flow

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

func newCore(t *testing.T) *core.Core {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ev, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ev.Close() })
	c, err := core.New(context.Background(), config.Config{DataDir: dir, RulesDir: dir}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestListener sends a real packet and finds the flow as an event, on the host the
// exporter's syslog would use.
func TestListener(t *testing.T) {
	c := newCore(t)
	ctx, cancel := context.WithCancel(context.Background())
	syslogHost, err := c.State.EnsureNetworkHost(ctx, "127.0.0.1", "fw", "OPNsense")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	l := New(c, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx, addr) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	eventually(t, c.Flow.Listening.Load)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Data before its template, then the template, then garbage.
	first := uint32(90000)
	conn.Write(v9Packet(100000, 1, set(300, v9Record("192.168.20.5", "1.1.1.1", 50000, 443, 1500, 10, first, 99000))))
	conn.Write(v9Packet(100000, 1, set(v9TemplateSet, tmpl(300, v9Fields...))))
	conn.Write([]byte{0, 99, 1})

	eventually(t, func() bool { return c.Flow.Records.Load() == 1 && c.Flow.Malformed.Load() == 1 })
	var res *events.SearchResult
	eventually(t, func() bool {
		res, err = c.Events.Search(ctx, events.SearchQuery{Query: "event.module:netflow", Limit: 10})
		return err == nil && len(res.Events) == 1
	})
	ev := res.Events[0]
	if ev.Host.ID != syslogHost.ID || ev.Source.IP != "192.168.20.5" || ev.Destination.Port != 443 || ev.Network.Bytes != 1500 || ev.Network.Direction != "outbound" {
		t.Fatalf("event %+v source %+v net %+v", ev.Host, ev.Source, ev.Network)
	}
	exp := c.Flow.Exporters()
	if len(exp) != 1 || exp[0].IP != "127.0.0.1" || exp[0].Records != 1 || exp[0].Templates != 1 {
		t.Fatalf("exporters %+v", exp)
	}
	if c.Flow.Waiting.Load() != 1 {
		t.Errorf("waiting %d", c.Flow.Waiting.Load())
	}
}

func TestListenerRefusesOthers(t *testing.T) {
	c := newCore(t)
	ctx, cancel := context.WithCancel(context.Background())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	l := New(c, []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")})
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx, addr) }()
	defer func() {
		cancel()
		<-done
	}()
	eventually(t, c.Flow.Listening.Load)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(v9Packet(100000, 1, set(v9TemplateSet, tmpl(300, v9Fields...))))
	eventually(t, func() bool { return c.Flow.Refused.Load() == 1 })
	if c.Flow.Packets.Load() != 0 {
		t.Errorf("packets %d", c.Flow.Packets.Load())
	}
}

// A full queue drops and counts packets rather than blocking the socket.
func TestQueueDropsWhenFull(t *testing.T) {
	c := newCore(t)
	l := New(c, nil)
	for range queueSize {
		l.in <- packet{}
	}
	select {
	case l.in <- packet{}:
		t.Fatal("queue is not bounded")
	default:
	}
}

func eventually(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
