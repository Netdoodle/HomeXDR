//go:build darwin

package darwin

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
)

// These run against the real system on macOS (the CI runners); none needs root.

func testEnv(t *testing.T) platform.Env {
	return platform.Env{AgentID: "test", DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestLiveProcessTable(t *testing.T) {
	ps, err := listProcs()
	if err != nil || len(ps) < 10 {
		t.Fatalf("listProcs: %d, %v", len(ps), err)
	}
	self := int64(os.Getpid())
	k, err := procByPID(self)
	if err != nil || k.PPID != int64(os.Getppid()) || k.Start == 0 {
		t.Fatalf("self = %+v, %v", k, err)
	}
	// The start key is p_starttime in microseconds: close to now for this test binary.
	if age := time.Since(startTimeFromMicros(k.Start)); age < 0 || age > 10*time.Minute {
		t.Fatalf("start time is %v ago", age)
	}
	exe, args, err := procArgs(self)
	want, _ := os.Executable()
	if err != nil || filepath.Base(exe) != filepath.Base(want) || len(args) == 0 {
		t.Fatalf("procArgs(self) = %q %q %v", exe, args, err)
	}
	if _, err := procByPID(999999); err == nil {
		t.Fatal("a missing PID was found")
	}
	if p := describe(testEnv(t), newLRU[string, procSummary](8), 1); p.Name != "launchd" {
		t.Fatalf("PID 1 = %+v", p)
	}
}

func TestLiveSockets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			time.Sleep(5 * time.Second)
			c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	es, err := readSockets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	self := int64(os.Getpid())
	var listen, est int
	for _, e := range es {
		if e.PID != self {
			continue
		}
		switch {
		case e.State == "LISTEN" && e.Local.String() == ln.Addr().String():
			listen++
		case e.State == "ESTABLISHED" && e.Remote.String() == ln.Addr().String():
			est++
		}
	}
	if listen != 1 || est != 1 {
		t.Fatalf("own sockets: listen %d established %d of %d entries", listen, est, len(es))
	}
}

func TestLiveSystemPlists(t *testing.T) {
	// Apple's own job definitions are a mix of XML and binary plists.
	files, _ := filepath.Glob("/System/Library/LaunchDaemons/*.plist")
	if len(files) < 50 {
		t.Fatalf("only %d system launch daemons", len(files))
	}
	var labels, bad int
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		j, err := parseLaunchdJob(b)
		if err != nil {
			bad++
			t.Logf("%s: %v", f, err)
			continue
		}
		if j.Label != "" {
			labels++
		}
	}
	if bad > 0 || labels < len(files)*9/10 {
		t.Fatalf("%d of %d failed, %d labelled", bad, len(files), labels)
	}
}

func TestLiveCollectors(t *testing.T) {
	cs := collectors(testEnv(t))
	for _, a := range api.Artifacts {
		has := false
		for _, p := range a.Platforms {
			has = has || p == "darwin"
		}
		if _, ok := cs[a.Name]; has != ok {
			t.Errorf("artifact %s: darwin in catalog %v, implemented %v", a.Name, has, ok)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, name := range []string{"system.info", "process.list", "network.connections", "users.list", "users.sessions", "persistence.autoruns", "services.list", "software.list"} {
		var rows []platform.Row
		err := cs[name](ctx, map[string]string{"hash": "false"}, func(r platform.Row) error {
			rows = append(rows, r)
			return nil
		})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		t.Logf("%s: %d rows", name, len(rows))
		switch name {
		case "system.info":
			if len(rows) != 1 || rows[0]["os_version"] == "" || rows[0]["machine_id"] == "" {
				t.Errorf("system.info = %v", rows)
			}
		case "users.list":
			found := false
			for _, r := range rows {
				found = found || r["name"] == "root"
			}
			if !found {
				t.Errorf("users.list has no root: %d rows", len(rows))
			}
		case "services.list", "software.list", "process.list":
			if len(rows) < 5 {
				t.Errorf("%s: %d rows", name, len(rows))
			}
		}
	}
}

func TestLiveHostInfo(t *testing.T) {
	h := hostInfo(context.Background())
	if h.OS.Version == "" || h.OS.Kernel == "" || h.MemoryBytes == 0 || h.BootTime == nil || h.MachineID == "" {
		t.Fatalf("host = %+v", h)
	}
	if strings.HasSuffix(h.Hostname, ".local") {
		t.Fatalf("hostname %q", h.Hostname)
	}
}

func TestLiveESLoggerEvents(t *testing.T) {
	sup, err := esSupported()
	if err != nil {
		t.Skipf("no eslogger: %v", err)
	}
	for _, e := range []string{"exec", "exit", "openssh_login", "lw_session_unlock", "btm_launch_item_add", "create", "close"} {
		if !sup[e] {
			t.Errorf("eslogger does not list %q", e)
		}
	}
}
