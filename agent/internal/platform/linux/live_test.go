//go:build linux

package linux

// Tests against the running kernel. The eBPF ones need root and BTF and are skipped
// otherwise; run them with `sudo go test ./internal/platform/linux/`.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Doodlebug12/homexdr/agent/internal/platform"
	"github.com/Doodlebug12/homexdr/shared/api"
	"github.com/Doodlebug12/homexdr/shared/event"
	"github.com/cilium/ebpf/ringbuf"
)

func testEnv(t *testing.T) platform.Env {
	return platform.Env{AgentID: "test-agent", DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// TestEBPFStartKeyMatchesProc checks that the start key computed from the eBPF event
// (task->group_leader->start_boottime / (1e9/USER_HZ)) equals /proc/<pid>/stat field 22
// for a live process, for the process itself and its parent, so entity IDs from the
// eBPF sensor join with everything that reads /proc.
func TestEBPFStartKeyMatchesProc(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	objs, links, err := loadProcessBPF()
	if err != nil {
		t.Skipf("eBPF unavailable: %v", err)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
	}()
	rd, err := ringbuf.NewReader(objs.ProcessEvents)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.Process.Pid)
	defer cmd.Process.Kill()

	var exec execRecord
	deadline := time.Now().Add(10 * time.Second)
	rd.SetDeadline(deadline)
	for {
		rec, err := rd.Read()
		if err != nil {
			t.Fatalf("no exec event for pid %d: %v", pid, err)
		}
		if len(rec.RawSample) >= 4 && rec.RawSample[0] == evExec {
			if r, err := parseExecRecord(rec.RawSample); err == nil && r.PID == pid {
				exec = r
				break
			}
		}
	}
	procKey, err := startKey(int64(pid))
	if err != nil {
		t.Fatal(err)
	}
	if got := StartKeyFromNS(exec.StartNS); got != procKey {
		t.Fatalf("start key: eBPF %d (start_boottime %d ns) != /proc %d", got, exec.StartNS, procKey)
	}
	selfKey, _ := startKey(int64(os.Getpid()))
	if exec.PPID != uint32(os.Getpid()) || StartKeyFromNS(exec.ParentNS) != selfKey {
		t.Fatalf("parent: ppid %d key %d, want %d key %d", exec.PPID, StartKeyFromNS(exec.ParentNS), os.Getpid(), selfKey)
	}
	if !slices.Equal(exec.Args, []string{"/bin/sleep", "30"}) || exec.Comm != "sleep" {
		t.Fatalf("args %q comm %q", exec.Args, exec.Comm)
	}
	t.Logf("pid %d start key %d (eBPF and /proc agree)", pid, procKey)

	// Exit with SIGKILL: one exit event for the process, wait status 9.
	cmd.Process.Kill()
	cmd.Wait()
	for {
		rec, err := rd.Read()
		if err != nil {
			t.Fatalf("no exit event: %v", err)
		}
		if len(rec.RawSample) >= 4 && rec.RawSample[0] == evExit {
			r, err := parseExitRecord(rec.RawSample)
			if err != nil || r.PID != pid {
				continue
			}
			if code, sig := decodeExit(r.Status); code != 137 || sig != 9 || StartKeyFromNS(r.StartNS) != procKey {
				t.Fatalf("exit: code %d sig %d key %d", code, sig, StartKeyFromNS(r.StartNS))
			}
			return
		}
	}
}

type sink struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (s *sink) Emit(e *event.Event) {
	s.mu.Lock()
	s.evs = append(s.evs, e)
	s.mu.Unlock()
}

func (s *sink) find(fn func(*event.Event) bool) *event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.evs {
		if fn(e) {
			return e
		}
	}
	return nil
}

func waitEvent(t *testing.T, s *sink, what string, fn func(*event.Event) bool) *event.Event {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if e := s.find(fn); e != nil {
			return e
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
	return nil
}

// TestProcessSensorEnrichment runs the whole process sensor (whichever implementation
// loads) and checks an exec event end to end.
func TestProcessSensorEnrichment(t *testing.T) {
	env := testEnv(t)
	s := newProcessSensor(api.ProcessSensorConfig{Enabled: true, HashExecutables: true}, env)
	out := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()
	defer func() {
		cancel()
		<-done
	}()
	time.Sleep(1500 * time.Millisecond) // let the sensor attach
	st := s.Status()
	t.Logf("process sensor impl=%s state=%s %s", st.Impl, st.State, st.Error)

	cmd := exec.Command("/bin/sleep", "3")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := int64(cmd.Process.Pid)
	defer cmd.Process.Kill()
	e := waitEvent(t, out, "exec event", func(e *event.Event) bool {
		return e.Process != nil && e.Process.PID == pid && slices.Contains(e.Event.Type, event.TypeStart)
	})
	key, _ := startKey(pid)
	if e.Process.EntityID != env.EntityID(pid, key) {
		t.Errorf("entity id %s, want %s", e.Process.EntityID, env.EntityID(pid, key))
	}
	selfKey, _ := startKey(int64(os.Getpid()))
	if e.Process.Parent == nil || e.Process.Parent.EntityID != env.EntityID(int64(os.Getpid()), selfKey) {
		t.Errorf("parent %+v", e.Process.Parent)
	}
	if !strings.HasSuffix(e.Process.Executable, "/sleep") || e.Process.CommandLine != "/bin/sleep 3" || e.Process.Name != "sleep" {
		t.Errorf("process %+v", e.Process)
	}
	if e.Process.User == nil || e.Process.User.ID != strconv.Itoa(os.Getuid()) || e.Process.Elevated == nil {
		t.Errorf("user %+v", e.Process.User)
	}
	if st.Impl != event.ModuleProcfs && (e.Process.Hash == nil || len(e.Process.Hash.SHA256) != 64) {
		t.Errorf("hash %+v", e.Process.Hash)
	}
	if e.Event.Module != st.Impl {
		t.Errorf("module %s, impl %s", e.Event.Module, st.Impl)
	}
	cmd.Process.Kill()
	cmd.Wait()
	if st.Impl == event.ModuleEBPF {
		x := waitEvent(t, out, "exit event", func(e *event.Event) bool {
			return e.Process != nil && e.Process.PID == pid && slices.Contains(e.Event.Type, event.TypeEnd)
		})
		if x.Process.EntityID != e.Process.EntityID || x.Process.ExitCode == nil || *x.Process.ExitCode != 137 {
			t.Errorf("exit %+v", x.Process)
		}
	}
}

// TestNetworkSensorEBPF connects to a local listener and expects connect and accept
// events attributed to this process.
func TestNetworkSensorEBPF(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	env := testEnv(t)
	s := newNetworkSensor(env)
	s.self = 0 // report the test's own connections
	out := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()
	defer func() {
		cancel()
		<-done
	}()
	time.Sleep(1500 * time.Millisecond)
	if st := s.Status(); st.Impl != event.ModuleEBPF {
		t.Skipf("eBPF unavailable: %s", st.Error)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	pid := int64(os.Getpid())
	conn := waitEvent(t, out, "outbound connect", func(e *event.Event) bool {
		return e.Network != nil && e.Network.Direction == event.DirectionOutbound && e.Destination.Port == port
	})
	if conn.Process == nil || conn.Process.PID != pid || conn.Source.IP != "127.0.0.1" || conn.Network.Transport != "tcp" || conn.Network.CommunityID != "" {
		t.Errorf("connect %+v %+v %+v", conn.Process, conn.Source, conn.Network)
	}
	acc := waitEvent(t, out, "inbound accept", func(e *event.Event) bool {
		return e.Network != nil && e.Network.Direction == event.DirectionInbound && e.Destination.Port == port
	})
	if acc.Process == nil || acc.Process.PID != pid || acc.Source.Port == port {
		t.Errorf("accept %+v %+v", acc.Process, acc.Source)
	}
	key, _ := startKey(pid)
	if conn.Process.EntityID != env.EntityID(pid, key) {
		t.Errorf("network entity id does not match /proc")
	}

	// A refused connection is reported as a failure.
	l2, _ := net.Listen("tcp4", "127.0.0.1:0")
	dead := l2.Addr().(*net.TCPAddr).Port
	l2.Close()
	net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(dead), time.Second)
	waitEvent(t, out, "failed connect", func(e *event.Event) bool {
		return e.Network != nil && e.Destination.Port == dead && e.Event.Outcome == event.OutcomeFailure
	})
}

func TestKillProcess(t *testing.T) {
	env := testEnv(t)
	for _, pid := range []int64{0, 1, int64(os.Getpid())} {
		if _, err := killProcess(env, api.KillParams{PID: pid}); err == nil {
			t.Errorf("kill %d allowed", pid)
		}
	}
	cmd := exec.Command("/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := int64(cmd.Process.Pid)
	if _, err := killProcess(env, api.KillParams{PID: pid, EntityID: "not-the-right-entity"}); err == nil {
		t.Fatal("entity mismatch did not prevent the kill")
	}
	key, _ := startKey(pid)
	res, err := killProcess(env, api.KillParams{PID: pid, EntityID: env.EntityID(pid, key)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Killed, []int64{pid}) {
		t.Fatalf("killed %v", res.Killed)
	}
	err = cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ProcessState.String() != "signal: killed" {
		t.Fatalf("wait: %v", err)
	}
}

func TestKillTree(t *testing.T) {
	env := testEnv(t)
	// A shell with two sleeping children.
	cmd := exec.Command("/bin/sh", "-c", "sleep 60 & sleep 60 & wait")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := int64(cmd.Process.Pid)
	deadline := time.Now().Add(5 * time.Second)
	for len(descendants(pid)) < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	kids := descendants(pid)
	if len(kids) < 2 {
		t.Fatalf("children not started: %v", kids)
	}
	res, err := killProcess(env, api.KillParams{PID: pid, Tree: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Killed) != 3 || res.Killed[0] != pid {
		t.Fatalf("killed %v", res.Killed)
	}
	cmd.Wait()
	time.Sleep(200 * time.Millisecond)
	for _, k := range kids {
		if st, err := readStat(k.pid); err == nil && st.State != 'Z' && st.StartTick == k.start {
			t.Errorf("child %d still alive (%c)", k.pid, st.State)
		}
	}
}

// TestNFTRulesetInNetns loads the generated ruleset into a throwaway network namespace
// with the real nft binary, to check that nft accepts it. It never touches the host's
// own namespace. Opt-in: HOMEXDR_NETNS_TEST=1, root, `ip` and `nft` installed (NFT may
// point at an nft binary).
func TestNFTRulesetInNetns(t *testing.T) {
	if os.Getenv("HOMEXDR_NETNS_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("set HOMEXDR_NETNS_TEST=1 and run as root")
	}
	ipBin, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("ip not installed")
	}
	nft := os.Getenv("NFT")
	if nft == "" {
		if nft, err = exec.LookPath("nft"); err != nil {
			t.Skip("nft not installed")
		}
	}
	ns := "hxtest-" + strconv.Itoa(os.Getpid())
	if out, err := exec.Command(ipBin, "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("netns add: %v %s", err, out)
	}
	defer exec.Command(ipBin, "netns", "delete", ns).Run()
	inNS := func(stdin string, args ...string) (string, error) {
		c := exec.Command(ipBin, append([]string{"netns", "exec", ns, nft}, args...)...)
		if stdin != "" {
			c.Stdin = strings.NewReader(stdin)
		}
		out, err := c.CombinedOutput()
		return string(out), err
	}
	iso := platform.Isolation{
		ServerIPs:  []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")},
		ServerPort: 8443,
		Allow:      []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:1::/64")},
	}
	dns := []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")}
	// Apply twice: the script must be idempotent.
	for range 2 {
		if out, err := inNS(nftRuleset(iso, dns), "-f", "-"); err != nil {
			t.Fatalf("nft rejected the ruleset: %v\n%s\n%s", err, out, nftRuleset(iso, dns))
		}
	}
	out, err := inNS("", "list", "table", "inet", nftTable)
	if err != nil {
		t.Fatalf("list: %v %s", err, out)
	}
	for _, want := range []string{"policy drop", "192.0.2.10", "tcp dport 8443", "198.51.100.0/24", "2001:db8:1::/64"} {
		if !strings.Contains(out, want) {
			t.Errorf("listed table lacks %q:\n%s", want, out)
		}
	}
	if out, err := inNS("", "delete", "table", "inet", nftTable); err != nil {
		t.Fatalf("delete: %v %s", err, out)
	}
	if _, err := inNS("", "list", "table", "inet", nftTable); err == nil {
		t.Fatal("table still present after release")
	}
}

// TestProcessFallbacks exercises the proc connector and /proc polling implementations.
func TestProcessFallbacks(t *testing.T) {
	impls := map[string]func(*processSensor, context.Context, platform.Emitter) error{
		"procfs": (*processSensor).runPoll,
	}
	if os.Geteuid() == 0 {
		impls["procconn"] = (*processSensor).runProcConn
	}
	for name, run := range impls {
		t.Run(name, func(t *testing.T) {
			env := testEnv(t)
			s := newProcessSensor(api.ProcessSensorConfig{Enabled: true, HashExecutables: true}, env)
			out := &sink{}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- run(s, ctx, out) }()
			defer func() {
				cancel()
				<-done
			}()
			time.Sleep(300 * time.Millisecond)
			select {
			case err := <-done:
				done <- err
				if isUnavailable(err) {
					t.Skipf("%s unavailable here: %v", name, err)
				}
				t.Fatalf("%s stopped: %v", name, err)
			default:
			}
			cmd := exec.Command("/bin/sleep", "3")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			pid := int64(cmd.Process.Pid)
			e := waitEvent(t, out, "exec event", func(e *event.Event) bool {
				return e.Process != nil && e.Process.PID == pid && slices.Contains(e.Event.Type, event.TypeStart)
			})
			key, _ := startKey(pid)
			if e.Process.EntityID != env.EntityID(pid, key) || e.Event.Module != name || e.Process.CommandLine != "/bin/sleep 3" {
				t.Errorf("%+v module %s", e.Process, e.Event.Module)
			}
			cmd.Process.Kill()
			cmd.Wait()
			x := waitEvent(t, out, "exit event", func(e *event.Event) bool {
				return e.Process != nil && e.Process.PID == pid && slices.Contains(e.Event.Type, event.TypeEnd)
			})
			if x.Process.EntityID != e.Process.EntityID {
				t.Errorf("exit entity %s", x.Process.EntityID)
			}
		})
	}
}

func TestFileSensor(t *testing.T) {
	type runner func(s *fileSensor, ctx context.Context, root string, out platform.Emitter) error
	impls := map[string]runner{
		"inotify": func(s *fileSensor, ctx context.Context, root string, out platform.Emitter) error {
			return s.runInotify(ctx, []string{root}, out)
		},
	}
	if os.Geteuid() == 0 {
		impls["fanotify"] = func(s *fileSensor, ctx context.Context, root string, out platform.Emitter) error {
			fa, rest, err := openFanotify([]string{root})
			if fa == nil || len(rest) > 0 {
				return fmt.Errorf("fanotify unavailable for %s: %v", root, err)
			}
			return s.runFanotify(ctx, fa, out)
		}
	}
	for name, run := range impls {
		t.Run(name, func(t *testing.T) {
			// t.TempDir is under /tmp, which is a real file system here (not tmpfs) on WSL;
			// on hosts where /tmp is tmpfs (<6.7) fanotify FID marks are refused.
			root := t.TempDir()
			existing := root + "/existing.conf"
			os.WriteFile(existing, []byte("a=1\n"), 0o644)
			env := testEnv(t)
			s := newFileSensor(api.FileSensorConfig{Enabled: true, Paths: []string{root}, Exclude: []string{"*.skip"}}, nil, env)
			s.self = 0 // report the test's own changes
			out := &sink{}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- run(s, ctx, root, out) }()
			defer func() {
				cancel()
				<-done
			}()
			time.Sleep(300 * time.Millisecond)
			select {
			case err := <-done:
				t.Skipf("%s not available: %v", name, err)
			default:
			}
			p := root + "/payload.sh"
			os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755)
			f, _ := os.OpenFile(existing, os.O_APPEND|os.O_WRONLY, 0)
			f.WriteString("b=2\n")
			f.Close()
			os.WriteFile(root+"/ignored.skip", []byte("x"), 0o644)
			os.Rename(p, root+"/renamed.sh")
			os.Remove(root + "/renamed.sh")
			want := func(action, path string) *event.Event {
				return waitEvent(t, out, action+" "+path, func(e *event.Event) bool {
					return e.File != nil && e.Event.Action == action && e.File.Path == path
				})
			}
			c := want("created", p)
			want("modified", existing)
			r := want("renamed", root+"/renamed.sh")
			want("deleted", root+"/renamed.sh")
			if r.File.OldPath != p {
				t.Errorf("rename old path %q", r.File.OldPath)
			}
			if name == "fanotify" && (c.Process == nil || c.Process.PID != int64(os.Getpid())) {
				t.Errorf("fanotify event not attributed: %+v", c.Process)
			}
			if e := out.find(func(e *event.Event) bool { return e.File != nil && strings.HasSuffix(e.File.Path, ".skip") }); e != nil {
				t.Error("excluded file reported")
			}
			// Creating a file also closes it after writing; that is folded into "created".
			if e := out.find(func(e *event.Event) bool { return e.File != nil && e.File.Path == p && e.Event.Action == "modified" }); e != nil {
				t.Error("write right after create reported separately")
			}
		})
	}
}

// TestAuthJournal sends a synthetic sshd message through logger(1) into journald.
func TestAuthJournal(t *testing.T) {
	jc, ok := journalAvailable()
	logger, err := exec.LookPath("logger")
	if !ok || err != nil || os.Geteuid() != 0 {
		t.Skip("needs root, journald and logger")
	}
	env := testEnv(t)
	s := newAuthSensor(env)
	out := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.runJournal(ctx, jc, out) }()
	defer func() {
		cancel()
		<-done
	}()
	time.Sleep(time.Second)
	user := "hxtest" + strconv.Itoa(os.Getpid())
	msg := "Failed password for invalid user " + user + " from 192.0.2.77 port 4242 ssh2"
	if out, err := exec.Command(logger, "-t", "sshd", "-p", "auth.info", msg).CombinedOutput(); err != nil {
		t.Fatalf("logger: %v %s", err, out)
	}
	e := waitEvent(t, out, "ssh failure", func(e *event.Event) bool { return e.User != nil && e.User.Name == user })
	if e.Event.Outcome != event.OutcomeFailure || e.Source.IP != "192.0.2.77" || e.Event.Action != "ssh_login" {
		t.Errorf("%+v %+v", e.Event, e.Source)
	}
}
