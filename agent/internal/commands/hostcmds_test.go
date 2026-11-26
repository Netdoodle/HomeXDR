package commands

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/spool"
	"github.com/Netdoodle/homexdr/shared/api"
)

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func hostCmd(typ, params string) *api.Command {
	return &api.Command{ID: "c1", Type: typ, Params: json.RawMessage(params)}
}

type execCall struct {
	name string
	args []string
}

// stubPower replaces the OS exec for the test.
func stubPower(t *testing.T, err error) *[]execCall {
	t.Helper()
	var calls []execCall
	old := powerExec
	powerExec = func(_ context.Context, name string, args ...string) error {
		calls = append(calls, execCall{name, args})
		return err
	}
	t.Cleanup(func() { powerExec = old })
	return &calls
}

func TestPreparePowerValidation(t *testing.T) {
	calls := stubPower(t, nil)
	h := &Handler{Log: quietLog}
	for _, typ := range []string{api.CmdHostReboot, api.CmdHostShutdown} {
		for _, bad := range []string{
			`{"delay_sec":-1}`, `{"delay_sec":3601}`, `{"delay_sec":"60"}`, `{"delay_sec":1.5}`,
			`{"message":"` + strings.Repeat("a", 201) + `"}`, `{"message":"line1\nline2"}`,
			`{"message":"bell\u0007"}`, `{"message":"nul\u0000"}`, `{"cmd":"rm -rf /"}`, `{"delay":5}`, `[1]`,
		} {
			if _, err := h.prepare(hostCmd(typ, bad)); err == nil {
				t.Errorf("%s accepted %s", typ, bad)
			}
		}
		for _, good := range []string{
			``, `{}`, `null`, `{"delay_sec":0}`, `{"delay_sec":3600}`,
			`{"message":"` + strings.Repeat("é", 200) + `"}`, `{"delay_sec":5,"message":"Maintenance: back in 5 min"}`,
		} {
			if _, err := h.prepare(hostCmd(typ, good)); err != nil {
				t.Errorf("%s rejected %s: %v", typ, good, err)
			}
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("prepare executed %v", *calls)
	}
}

func TestPowerRunDefaultsAndResult(t *testing.T) {
	calls := stubPower(t, nil)
	h := &Handler{Log: quietLog}
	run, err := h.prepare(hostCmd(api.CmdHostReboot, `{}`)) // a missing delay_sec means 60
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	out, _, err := run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	res := out.(api.HostPowerResult)
	at, err := time.Parse(time.RFC3339, res.ScheduledFor)
	if err != nil || res.DelaySec != 60 || at.Before(before.Add(59*time.Second)) || at.After(time.Now().Add(61*time.Second)) {
		t.Fatalf("result %+v (%v)", res, err)
	}
	if len(*calls) != 1 {
		t.Fatalf("calls: %v", *calls)
	}
	// Explicit zero stays zero.
	run, _ = h.prepare(hostCmd(api.CmdHostShutdown, `{"delay_sec":0}`))
	out, _, _ = run(context.Background())
	if out.(api.HostPowerResult).DelaySec != 0 {
		t.Fatalf("explicit 0 became %+v", out)
	}
	// The OS refusing the request fails the command.
	stubPower(t, errors.New("shutdown: already scheduled"))
	run, _ = h.prepare(hostCmd(api.CmdHostReboot, `{}`))
	if _, _, err := run(context.Background()); err == nil {
		t.Fatal("exec error was swallowed")
	}
}

func TestShutdownArgv(t *testing.T) {
	cases := []struct {
		name     string
		got      []string
		want     []string
		whenWant string
	}{
		{"unix reboot 60s", unixShutdownArgv(false, 60, "msg"), []string{"-r", "+1", "msg"}, ""},
		{"unix reboot 61s rounds up", unixShutdownArgv(false, 61, ""), []string{"-r", "+2"}, ""},
		{"unix shutdown 1s", unixShutdownArgv(true, 1, ""), []string{"-h", "+1"}, ""},
		{"unix shutdown 3600s", unixShutdownArgv(true, 3600, "bye"), []string{"-h", "+60", "bye"}, ""},
		{"unix immediate", unixShutdownArgv(false, 0, ""), []string{"-r", "now"}, ""},
		{"windows reboot", windowsShutdownArgv(false, 60, "msg with spaces"), []string{"/r", "/t", "60", "/c", "msg with spaces"}, ""},
		{"windows shutdown no message", windowsShutdownArgv(true, 0, ""), []string{"/s", "/t", "0"}, ""},
	}
	for _, c := range cases {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
	// The argv of this build's OS is the one that is run, and the message is one argument.
	name, argv := shutdownCommand(true, api.HostPowerParams{DelaySec: 120, Message: `a "quoted" msg; rm -rf /`})
	if name == "" {
		t.Fatal("no program")
	}
	want := unixShutdownArgv(true, 120, `a "quoted" msg; rm -rf /`)
	if runtime.GOOS == "linux" {
		want[0] = "-P" // power off, not just halt
	}
	if runtime.GOOS == "windows" {
		want = windowsShutdownArgv(true, 120, `a "quoted" msg; rm -rf /`)
		if !strings.HasSuffix(strings.ToLower(name), `shutdown.exe`) {
			t.Errorf("program %q", name)
		}
	}
	if !slices.Equal(argv, want) {
		t.Errorf("native argv %q, want %q", argv, want)
	}
}

func TestPrepareRestart(t *testing.T) {
	if _, err := (&Handler{Log: quietLog}).prepare(hostCmd(api.CmdAgentRestart, `{}`)); err == nil {
		t.Fatal("accepted without a restart hook")
	}
	var fired atomic.Int32
	h := &Handler{Log: quietLog, Restart: func() { fired.Add(1) }, RestartDelay: 30 * time.Millisecond}
	if _, err := h.prepare(hostCmd(api.CmdAgentRestart, `{"force":true}`)); err == nil {
		t.Fatal("accepted params")
	}
	run, err := h.prepare(hostCmd(api.CmdAgentRestart, ``))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fired.Load() != 0 {
		t.Fatal("restart ran before the result could be posted")
	}
	time.Sleep(300 * time.Millisecond)
	if fired.Load() != 1 {
		t.Fatalf("restart fired %d times", fired.Load())
	}
}

func TestFlushQueue(t *testing.T) {
	if _, err := (&Handler{Log: quietLog}).prepare(hostCmd(api.CmdAgentFlushQueue, `{}`)); err == nil {
		t.Fatal("accepted without a spool")
	}
	sp, err := spool.Open(t.TempDir(), 8<<20, quietLog)
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	for i := range 20 {
		if err := sp.Append([]byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handler{Log: quietLog, Spool: sp}
	if _, err := h.prepare(hostCmd(api.CmdAgentFlushQueue, `{"keep":1}`)); err == nil {
		t.Fatal("accepted params")
	}
	run, err := h.prepare(hostCmd(api.CmdAgentFlushQueue, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := run(context.Background())
	res := out.(api.FlushQueueResult)
	if err != nil || res.EventsDropped != 20 || res.BytesDropped <= 0 {
		t.Fatalf("%+v %v", res, err)
	}
	b, _ := json.Marshal(res)
	if string(b) != fmt.Sprintf(`{"events_dropped":20,"bytes_dropped":%d}`, res.BytesDropped) {
		t.Fatalf("output shape %s", b)
	}
	if st := sp.Stats(); st.Events != 0 {
		t.Fatalf("%d events left", st.Events)
	}
}

func TestTimeouts(t *testing.T) {
	if timeout(api.CmdAgentLogs) != 10*time.Minute {
		t.Errorf("logs timeout %v", timeout(api.CmdAgentLogs))
	}
	for _, typ := range []string{api.CmdHostReboot, api.CmdHostShutdown, api.CmdAgentRestart, api.CmdAgentFlushQueue} {
		if timeout(typ) != timeout("other") {
			t.Errorf("%s has a special timeout", typ)
		}
	}
}

func TestDefaultPolicyIncludesNewCommands(t *testing.T) {
	for _, typ := range []string{api.CmdHostReboot, api.CmdHostShutdown, api.CmdAgentRestart, api.CmdAgentLogs, api.CmdAgentFlushQueue} {
		if !slices.Contains(api.DefaultAllowedActions, typ) {
			t.Errorf("%s not in the default policy", typ)
		}
	}
}

func TestPlanLogs(t *testing.T) {
	dir := filepath.Join("data")
	w := planLogs("windows", dir, false)
	if len(w.Files) != 2 || w.Files[0] != filepath.Join(dir, "logs", "agent.log") || w.Files[1] != filepath.Join(dir, "logs", "agent.log.1") || w.Journal {
		t.Errorf("windows: %+v", w)
	}
	if m := planLogs("darwin", dir, false); m.Files[0] != "/Library/Logs/HomeXDR/agent.log" || len(m.Globs) != 1 {
		t.Errorf("darwin: %+v", m)
	}
	if l := planLogs("linux", dir, true); !l.Journal || len(l.Files) != 0 {
		t.Errorf("systemd: %+v", l)
	}
	if l := planLogs("linux", dir, false); l.Journal || len(l.Syslog) == 0 {
		t.Errorf("no systemd: %+v", l)
	}
}

func zipFiles(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(data)
	}
	return out
}

func TestBuildLogBundle(t *testing.T) {
	data := t.TempDir()
	logs := filepath.Join(data, "logs")
	os.MkdirAll(logs, 0o700)
	os.WriteFile(filepath.Join(logs, "agent.log"), []byte("current\n"), 0o600)
	os.WriteFile(filepath.Join(logs, "agent.log.1"), []byte("previous\n"), 0o600)
	os.WriteFile(filepath.Join(data, "status.json"), []byte(`{"pid":1}`), 0o600)
	// Things that must never end up in the bundle.
	os.WriteFile(filepath.Join(data, "agent.key"), []byte("SECRET-KEY"), 0o600)
	os.WriteFile(filepath.Join(data, "config.json"), []byte("SECRET-CONFIG"), 0o600)

	old := runJournal
	runJournal = func(_ context.Context, w io.Writer) error { _, err := io.WriteString(w, "journal line\n"); return err }
	defer func() { runJournal = old }()

	var buf bytes.Buffer
	plan := planLogs("windows", data, false)
	plan.Journal = true
	if err := buildLogBundle(context.Background(), &buf, plan, data); err != nil {
		t.Fatal(err)
	}
	files := zipFiles(t, buf.Bytes())
	for name, want := range map[string]string{"agent.log": "current\n", "agent.log.1": "previous\n", "status.json": `{"pid":1}`, "journal.txt": "journal line\n"} {
		if files[name] != want {
			t.Errorf("%s = %q, want %q", name, files[name], want)
		}
	}
	for name, content := range files {
		if strings.Contains(content, "SECRET") || strings.Contains(name, "key") || strings.Contains(name, "config") {
			t.Errorf("secret leaked in %s", name)
		}
	}
	if !strings.Contains(files["NOTES.txt"], "collected") {
		t.Errorf("notes: %q", files["NOTES.txt"])
	}

	// A failing journalctl and missing files are reported, not fatal.
	runJournal = func(context.Context, io.Writer) error { return errors.New("journalctl: not found") }
	buf.Reset()
	if err := buildLogBundle(context.Background(), &buf, logPlan{Journal: true, Files: []string{filepath.Join(data, "nope.log")}}, ""); err != nil {
		t.Fatal(err)
	}
	notes := zipFiles(t, buf.Bytes())["NOTES.txt"]
	if !strings.Contains(notes, "not found") || !strings.Contains(notes, "no agent log was found") {
		t.Errorf("notes: %q", notes)
	}
}

func TestBuildLogBundleCap(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "agent.log")
	f, _ := os.Create(big)
	line := strings.Repeat("x", 99) + "\n"
	for i := 0; i < (MaxLogBundleBytes/100)+50000; i++ { // ~55 MB
		f.WriteString(line)
	}
	f.WriteString("LAST LINE\n")
	f.Close()
	var buf bytes.Buffer
	if err := buildLogBundle(context.Background(), &buf, logPlan{Files: []string{big, big + ".1"}}, ""); err != nil {
		t.Fatal(err)
	}
	got := zipFiles(t, buf.Bytes())["agent.log"]
	if len(got) > MaxLogBundleBytes || !strings.HasSuffix(got, "LAST LINE\n") || !strings.HasPrefix(got, "x") {
		t.Fatalf("size %d, tail kept: %v", len(got), strings.HasSuffix(got, "LAST LINE\n"))
	}
}

func TestBuildLogBundleSyslog(t *testing.T) {
	dir := t.TempDir()
	sl := filepath.Join(dir, "syslog")
	os.WriteFile(sl, []byte("a other\nb homexdr-agent: one\nc other\nd homexdr-agent: two\n"), 0o600)
	var buf bytes.Buffer
	if err := buildLogBundle(context.Background(), &buf, logPlan{Syslog: []string{filepath.Join(dir, "missing"), sl}}, ""); err != nil {
		t.Fatal(err)
	}
	got := zipFiles(t, buf.Bytes())["syslog-syslog.txt"]
	if got != "b homexdr-agent: one\nd homexdr-agent: two\n" {
		t.Fatalf("got %q", got)
	}
}

type uploadAPI struct {
	API
	name string
	body []byte
}

func (u *uploadAPI) Upload(_ context.Context, _, name string, body io.Reader, size int64) error {
	u.name = name
	u.body, _ = io.ReadAll(body)
	if int64(len(u.body)) != size {
		return fmt.Errorf("size %d, read %d", size, len(u.body))
	}
	return nil
}

func TestAgentLogsUpload(t *testing.T) {
	data := t.TempDir()
	os.WriteFile(filepath.Join(data, "status.json"), []byte(`{"pid":7}`), 0o600)
	up := &uploadAPI{}
	h := &Handler{Log: quietLog, API: up, DataDir: data}
	if _, err := h.prepare(hostCmd(api.CmdAgentLogs, `{"all":true}`)); err == nil {
		t.Fatal("accepted params")
	}
	run, err := h.prepare(hostCmd(api.CmdAgentLogs, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	res := out.(api.FileHashResult)
	if !strings.HasPrefix(res.Path, "homexdr-agent-logs-") || !strings.HasSuffix(res.Path, ".zip") || res.Path != up.name {
		t.Errorf("name %q / %q", res.Path, up.name)
	}
	if res.Size != int64(len(up.body)) || len(res.SHA256) != 64 || len(res.MD5) != 32 || len(res.SHA1) != 40 {
		t.Errorf("result %+v", res)
	}
	if zipFiles(t, up.body)["status.json"] != `{"pid":7}` {
		t.Error("status.json missing from the upload")
	}
	if left, _ := filepath.Glob(filepath.Join(data, ".agent-logs-*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}
