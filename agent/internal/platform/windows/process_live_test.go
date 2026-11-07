//go:build windows

package windows

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
	"golang.org/x/sys/windows"
)

// Live tests against this machine. None of them changes system settings.

func TestSnapshotIncludesSelf(t *testing.T) {
	m := newProcMapper(testEnv(t), newWinProcs(), nil)
	n, err := m.loadSnapshot()
	if err != nil {
		t.Logf("snapshot incomplete: %v", err)
	}
	if n < 2 {
		t.Fatalf("snapshot found %d processes", n)
	}
	pid := int64(os.Getpid())
	e := m.table.get(pid, time.Time{})
	if e == nil {
		t.Fatal("own process not in the snapshot")
	}
	exe, _ := os.Executable()
	if !strings.EqualFold(e.Executable, exe) {
		t.Errorf("executable = %q, want %q", e.Executable, exe)
	}
	if !strings.Contains(strings.ToLower(e.CommandLine), strings.ToLower(filepath.Base(exe))) {
		t.Errorf("command line = %q", e.CommandLine)
	}
	var c, x, k, u windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &c, &x, &k, &u); err != nil {
		t.Fatal(err)
	}
	if e.Key != filetimeKey(c) || e.EntityID != m.env.EntityID(pid, filetimeKey(c)) {
		t.Errorf("start key %d, want the creation time %d", e.Key, filetimeKey(c))
	}
	if e.User == nil || e.User.ID == "" || e.User.Name == "" {
		t.Errorf("user = %+v", e.User)
	}
	if e.ParentEntityID == "" {
		t.Error("the test process's parent (go test) should be in the snapshot")
	}
}

func TestLiveProcessDetails(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(`C:\Windows\System32\cmd.exe`, "/c", "ping -n 30 127.0.0.1 >nul")
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	pid := int64(cmd.Process.Pid)
	src := newWinProcs()
	var lp *liveProc
	for range 50 {
		var ok bool
		if lp, ok = src.open(pid, wantDetails|wantCwd); ok && lp.WorkingDirectory != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lp == nil {
		t.Fatal("cannot open the child process")
	}
	if !strings.EqualFold(lp.Executable, `C:\Windows\System32\cmd.exe`) {
		t.Errorf("executable = %q", lp.Executable)
	}
	if !strings.Contains(lp.CommandLine, "ping -n 30 127.0.0.1") {
		t.Errorf("command line = %q", lp.CommandLine)
	}
	if !strings.EqualFold(strings.TrimSuffix(lp.WorkingDirectory, `\`), dir) {
		t.Errorf("working directory = %q, want %q", lp.WorkingDirectory, dir)
	}
	if lp.UserSID == "" || !lp.HasSession {
		t.Errorf("user SID %q, session %v", lp.UserSID, lp.HasSession)
	}
	if age := time.Since(lp.createdAt()); age < 0 || age > time.Minute {
		t.Errorf("creation time %v is off", lp.createdAt())
	}
	if _, ok := src.open(0, 0); ok {
		t.Error("PID 0 should not open")
	}
}

func TestVersionInfo(t *testing.T) {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	c := newPECache()
	pe := c.lookup(path)
	if pe == nil {
		t.Fatal("no version resource for cmd.exe")
	}
	if !strings.EqualFold(pe.OriginalFileName, "cmd.exe") || pe.Company != "Microsoft Corporation" ||
		pe.Product == "" || pe.Description == "" || pe.FileVersion == "" {
		t.Errorf("pe = %+v", pe)
	}
	pe.Company = "changed"
	if again := c.lookup(path); again == nil || again.Company != "Microsoft Corporation" {
		t.Error("cached value was modified through a returned copy")
	}
	if c.lookup("cmd.exe") != nil {
		t.Error("relative paths must not be looked up")
	}
	exe, _ := os.Executable()
	if pe := c.lookup(exe); pe != nil {
		t.Logf("test binary has a version resource: %+v", pe)
	}
}

func TestHasher(t *testing.T) {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	want, err := fsutil.SHA256File(path, maxHashBytes)
	if err != nil {
		t.Fatal(err)
	}
	s := &processSensor{}
	h := newHasher(1)
	out := &collectEmitter{}
	mk := func() *event.Event {
		return &event.Event{Event: event.Meta{Action: "exec"}, Process: &event.Process{Executable: path}}
	}
	first := mk()
	s.emit(first, h, out)
	// The second one waits until the first is hashed, then comes from the cache.
	deadline := time.Now().Add(10 * time.Second)
	for out.find(func(e *event.Event) bool { return e == first }) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	second := mk()
	s.emit(second, h, out)
	if second.Process.Hash == nil || second.Process.Hash.SHA256 != want {
		t.Errorf("cached hash = %+v", second.Process.Hash)
	}
	// A start event that already has a SHA-256 (Sysmon) is sent as it is, and so are
	// exits and paths that are not absolute.
	given := mk()
	given.Process.Hash = &event.Hash{SHA256: "given", MD5: "m"}
	s.emit(given, h, out)
	rel := mk()
	rel.Process.Executable = "Registry"
	s.emit(rel, h, out)
	h.stop()
	if first.Process.Hash == nil || first.Process.Hash.SHA256 != want {
		t.Errorf("worker hash = %+v, want %s", first.Process.Hash, want)
	}
	if given.Process.Hash.SHA256 != "given" || rel.Process.Hash != nil {
		t.Error("events that need no hashing were changed")
	}
	if len(out.evs) != 4 {
		t.Errorf("emitted %d events, want 4", len(out.evs))
	}
}

func TestQueryProcessAudit(t *testing.T) {
	on, set, err := QueryCommandLineAuditing()
	if err != nil {
		t.Fatalf("QueryCommandLineAuditing: %v", err)
	}
	t.Logf("ProcessCreationIncludeCmdLine_Enabled: enabled=%v set=%v", on, set)
	p, err := QueryProcessAudit()
	if err != nil {
		if !elevated() && (errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) || errors.Is(err, windows.ERROR_ACCESS_DENIED)) {
			if p.CommandLine != on || p.CommandLineSet != set {
				t.Errorf("partial result lost the registry value: %+v", p)
			}
			t.Skipf("reading the audit policy needs elevation: %v", err)
		}
		t.Fatalf("QueryProcessAudit: %v", err)
	}
	t.Logf("audit policy: creation=%s termination=%s", p.Creation, p.Termination)
}

func TestAuditFlagsString(t *testing.T) {
	for f, want := range map[AuditFlags]string{AuditNone: "none", AuditSuccess: "success", AuditFailure: "failure", AuditSuccess | AuditFailure: "success and failure"} {
		if got := f.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", f, got, want)
		}
	}
	if AuditProcessCreation.String() != "{0CCE922B-69AE-11D9-BED3-505054503030}" ||
		AuditProcessTermination.String() != "{0CCE922C-69AE-11D9-BED3-505054503030}" {
		t.Error("subcategory GUIDs")
	}
}

type collectEmitter struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (c *collectEmitter) Emit(e *event.Event) {
	c.mu.Lock()
	c.evs = append(c.evs, e)
	c.mu.Unlock()
}

func (c *collectEmitter) find(f func(*event.Event) bool) *event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.evs {
		if f(e) {
			return e
		}
	}
	return nil
}

// TestProcessSensorUnelevated checks that, without Sysmon and without the rights to
// read the Security log, the sensor fails with a message that says why.
func TestProcessSensorUnelevated(t *testing.T) {
	if elevated() {
		t.Skip("elevated: see TestProcessSensorLive")
	}
	if ok, err := channelEnabled(sysmonChannel); err == nil && ok {
		t.Skip("Sysmon is installed")
	}
	s := newProcessSensor(api.ProcessSensorConfig{Enabled: true}, testEnv(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := s.Run(ctx, &collectEmitter{})
	if !errors.Is(err, errAccessDenied) || !strings.Contains(err.Error(), "SYSTEM or administrator") {
		t.Fatalf("Run err = %v", err)
	}
	st := s.Status()
	if st.Name != "process" || st.Impl != event.ModuleEventLog || st.State != api.SensorFailed || st.Error == "" {
		t.Errorf("status = %+v", st)
	}
}

// TestProcessSensorLive runs the sensor against the real source and starts a process.
// It needs elevation, and Sysmon or process creation auditing.
func TestProcessSensorLive(t *testing.T) {
	if !elevated() {
		t.Skip("reading the Sysmon or Security log needs elevation")
	}
	env := testEnv(t)
	s := newProcessSensor(api.ProcessSensorConfig{Enabled: true, HashExecutables: true}, env)
	out := &collectEmitter{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	time.Sleep(2 * time.Second)
	st := s.Status()
	t.Logf("status: %+v", st)
	if st.State == api.SensorFailed {
		t.Fatalf("sensor failed: %s", st.Error)
	}
	if st.State == api.SensorDegraded && strings.Contains(st.Error, `"Audit Process Creation" is off`) {
		t.Skip("no Sysmon and process creation auditing is off: " + st.Error)
	}
	cmd := exec.Command(`C:\Windows\System32\cmd.exe`, "/c", "exit 3")
	if err := cmd.Run(); err == nil {
		t.Fatal("cmd /c exit 3 succeeded")
	}
	pid := int64(cmd.ProcessState.Pid())
	deadline := time.Now().Add(20 * time.Second)
	var start *event.Event
	for time.Now().Before(deadline) && start == nil {
		start = out.find(func(e *event.Event) bool {
			return e.Process != nil && e.Process.PID == pid && e.Event.Action == "exec"
		})
		time.Sleep(100 * time.Millisecond)
	}
	if start == nil {
		t.Fatalf("no start event for PID %d", pid)
	}
	p := start.Process
	t.Logf("start: %+v parent: %+v", p, p.Parent)
	if !strings.EqualFold(p.Executable, `C:\Windows\System32\cmd.exe`) || p.EntityID == "" || p.User == nil {
		t.Errorf("start process = %+v", p)
	}
	if p.Parent == nil || p.Parent.PID != int64(os.Getpid()) || p.Parent.EntityID == "" {
		t.Errorf("parent = %+v, want this test process", p.Parent)
	}
	if p.PE == nil || !strings.EqualFold(p.PE.OriginalFileName, "cmd.exe") {
		t.Errorf("pe = %+v", p.PE)
	}
}
