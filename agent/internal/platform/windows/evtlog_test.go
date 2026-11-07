//go:build windows

package windows

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestParseEventXMLSysmon(t *testing.T) {
	r, err := parseEventXML(sysmonStartXML)
	if err != nil {
		t.Fatal(err)
	}
	if r.Provider != "Microsoft-Windows-Sysmon" || r.EventID != 1 || r.Version != 5 || r.Level != 4 {
		t.Errorf("system fields: %+v", r)
	}
	if want := time.Date(2026, 11, 7, 10, 15, 30, 123456700, time.UTC); !r.TimeCreated.Equal(want) {
		t.Errorf("TimeCreated = %v, want %v", r.TimeCreated, want)
	}
	if r.RecordID != 48211 || r.Channel != sysmonChannel || r.Computer != "DESKTOP-HX01" {
		t.Errorf("record/channel/computer: %d %q %q", r.RecordID, r.Channel, r.Computer)
	}
	if r.ProcessID != 3120 || r.ThreadID != 4412 || r.UserSID != "S-1-5-18" {
		t.Errorf("execution/security: %d %d %q", r.ProcessID, r.ThreadID, r.UserSID)
	}
	if got := r.Data["Image"]; got != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` {
		t.Errorf("Image = %q", got)
	}
	if got := r.Data["Product"]; got != "Microsoft® Windows® Operating System" {
		t.Errorf("Product = %q", got)
	}
	if got := r.Data["ParentCommandLine"]; got != `"C:\Windows\system32\cmd.exe" ` {
		t.Errorf("ParentCommandLine = %q (trailing space must be kept)", got)
	}
	if len(r.Strings) != 0 {
		t.Errorf("Strings = %q", r.Strings)
	}
}

func TestParseEventXMLClassic(t *testing.T) {
	const x = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>` +
		`<Provider Name='HomeXDR-Test'/><EventID Qualifiers='0'>1000</EventID><Version>0</Version><Level>4</Level>` +
		`<Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2026-11-07T08:00:00.000000000Z'/>` +
		`<EventRecordID>77</EventRecordID><Channel>Application</Channel><Computer>pc</Computer><Security/></System>` +
		`<EventData><Data>first</Data><Data>second &amp; more</Data><Binary>00FF</Binary></EventData></Event>`
	r, err := parseEventXML(x)
	if err != nil {
		t.Fatal(err)
	}
	if r.Provider != "HomeXDR-Test" || r.EventID != 1000 || r.Channel != "Application" || r.RecordID != 77 {
		t.Errorf("system fields: %+v", r)
	}
	if len(r.Strings) != 2 || r.Strings[0] != "first" || r.Strings[1] != "second & more" {
		t.Errorf("Strings = %q", r.Strings)
	}
}

func TestParseEventXMLUserData(t *testing.T) {
	const x = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>` +
		`<Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1102</EventID>` +
		`<TimeCreated SystemTime='2026-11-07T08:00:00Z'/><EventRecordID>5</EventRecordID><Channel>Security</Channel>` +
		`<Computer>pc</Computer></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>` +
		`<SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid><SubjectUserName>alice</SubjectUserName>` +
		`<SubjectDomainName>HX01</SubjectDomainName><SubjectLogonId>0x1f2e3</SubjectLogonId></LogFileCleared></UserData></Event>`
	r, err := parseEventXML(x)
	if err != nil {
		t.Fatal(err)
	}
	if r.EventID != 1102 || r.Data["SubjectUserName"] != "alice" || r.Data["SubjectLogonId"] != "0x1f2e3" {
		t.Errorf("record: %+v", r)
	}
}

func TestParseEventXMLControlCharacters(t *testing.T) {
	x := strings.Replace(securityStartXML, "net localgroup", "net\x01localgroup&#x2;", 1)
	r, err := parseEventXML(x)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Data["CommandLine"]; !strings.HasPrefix(got, "net\uFFFDlocalgroup\uFFFD") {
		t.Errorf("CommandLine = %q", got)
	}
}

func TestBookmarkFile(t *testing.T) {
	got := bookmarkFile(`C:\data`, "process", sysmonChannel)
	if want := `C:\data\eventlog\process-microsoft-windows-sysmon_operational.bookmark`; got != want {
		t.Errorf("bookmarkFile = %q, want %q", got, want)
	}
	if bookmarkFile("", "process", "Security") != "" {
		t.Error("no data dir must disable bookmarks")
	}
}

func TestChannelErrors(t *testing.T) {
	const missing = "HomeXDR-Missing-Channel/Operational"
	if _, err := channelEnabled(missing); !errors.Is(err, errChannelNotFound) {
		t.Errorf("channelEnabled(missing) err = %v, want errChannelNotFound", err)
	}
	if _, err := subscribe(subscribeOptions{Channel: missing, Log: testLog()}); !errors.Is(err, errChannelNotFound) {
		t.Errorf("subscribe(missing) err = %v, want errChannelNotFound", err)
	}
	if ok, err := channelEnabled("Application"); err != nil || !ok {
		t.Errorf("channelEnabled(Application) = %v, %v", ok, err)
	}
}

func TestSecurityChannelAccess(t *testing.T) {
	s, err := subscribe(subscribeOptions{Channel: securityChannel, Query: securityQuery, Log: testLog()})
	if elevated() {
		if err != nil {
			t.Fatalf("elevated subscribe to Security: %v", err)
		}
		s.Close()
		return
	}
	if err == nil {
		s.Close()
		t.Skip("this account can read the Security log without elevation (Event Log Readers?)")
	}
	if !errors.Is(err, errAccessDenied) {
		t.Fatalf("unelevated subscribe to Security: err = %v, want errAccessDenied", err)
	}
}

// TestEventLogLive writes records to the Application log (which any user may do) and
// checks that a subscription receives them, that a saved position resumes after the
// last handled record with no duplicates and no gaps, and that without a saved
// position only new records are delivered.
func TestEventLogLive(t *testing.T) {
	const source = "HomeXDR-Test"
	query := "*[System[Provider[@Name='" + source + "']]]"
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	bm := filepath.Join(t.TempDir(), "eventlog", "test-application.bookmark")
	opts := subscribeOptions{Channel: "Application", Query: query, BookmarkFile: bm, Log: testLog()}

	// Written before the first subscription: without a saved position it must not be
	// delivered.
	writeAppEvent(t, source, nonce+"-before")
	waitNewest(t, "Application", query, nonce+"-before")

	s1, err := subscribe(opts)
	if err != nil {
		t.Fatal(err)
	}
	if s1.resumed {
		t.Error("first subscription claims to resume from a bookmark")
	}
	if _, err := os.Stat(bm); err != nil {
		t.Errorf("initial position not saved: %v", err)
	}
	recs1, stop1 := runSubscription(t, s1)
	writeAppEvent(t, source, nonce+"-1")
	got := collect(t, recs1, nonce, nonce+"-1")
	if want := []string{nonce + "-1"}; !equalStrings(got, want) {
		t.Errorf("first run got %q, want %q", got, want)
	}
	stop1()

	// Written while the agent is "stopped".
	writeAppEvent(t, source, nonce+"-2")
	writeAppEvent(t, source, nonce+"-3")

	s2, err := subscribe(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.resumed {
		t.Error("second subscription did not resume from the saved bookmark")
	}
	recs2, stop2 := runSubscription(t, s2)
	writeAppEvent(t, source, nonce+"-4")
	got = collect(t, recs2, nonce, nonce+"-4")
	if want := []string{nonce + "-2", nonce + "-3", nonce + "-4"}; !equalStrings(got, want) {
		t.Errorf("after restart got %q, want %q", got, want)
	}
	stop2()

	// A corrupt bookmark is ignored: the subscription starts at new records.
	if err := os.WriteFile(bm, []byte("not a bookmark"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3, err := subscribe(opts)
	if err != nil {
		t.Fatal(err)
	}
	if s3.resumed {
		t.Error("subscription resumed from a corrupt bookmark")
	}
	recs3, stop3 := runSubscription(t, s3)
	writeAppEvent(t, source, nonce+"-5")
	got = collect(t, recs3, nonce, nonce+"-5")
	if want := []string{nonce + "-5"}; !equalStrings(got, want) {
		t.Errorf("after corrupt bookmark got %q, want %q", got, want)
	}
	stop3()
}

func runSubscription(t *testing.T, s *subscription) (<-chan *Record, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *Record, 256)
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, func(r *Record) { ch <- r }) }()
	return ch, func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
		s.Close()
	}
}

// collect returns the first string of each record carrying nonce, until last arrives.
func collect(t *testing.T, ch <-chan *Record, nonce, last string) []string {
	t.Helper()
	var got []string
	timeout := time.After(20 * time.Second)
	for {
		select {
		case r := <-ch:
			if len(r.Strings) == 0 || !strings.HasPrefix(r.Strings[0], nonce) {
				continue
			}
			if r.Channel != "Application" || r.Provider != "HomeXDR-Test" || r.RecordID == 0 || r.TimeCreated.IsZero() {
				t.Errorf("record fields: %+v", r)
			}
			got = append(got, r.Strings[0])
			if r.Strings[0] == last {
				return got
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %q; got %q", last, got)
		}
	}
}

func writeAppEvent(t *testing.T, source, msg string) {
	t.Helper()
	src, err := windows.UTF16PtrFromString(source)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.RegisterEventSource(nil, src)
	if err != nil {
		t.Fatalf("RegisterEventSource: %v", err)
	}
	defer windows.DeregisterEventSource(h)
	m, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		t.Fatal(err)
	}
	strs := []*uint16{m}
	if err := windows.ReportEvent(h, windows.EVENTLOG_INFORMATION_TYPE, 0, 1000, 0, 1, 0, &strs[0], nil); err != nil {
		t.Fatalf("ReportEvent: %v", err)
	}
}

// waitNewest waits until the newest record matching query carries want.
func waitNewest(t *testing.T, channel, query, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var buf []uint16
	for time.Now().Before(deadline) {
		if s := newestRecordXML(t, channel, query, &buf); strings.Contains(s, want) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("record %q never became visible", want)
}

func newestRecordXML(t *testing.T, channel, query string, buf *[]uint16) string {
	ch, _ := windows.UTF16PtrFromString(channel)
	q, _ := windows.UTF16PtrFromString(query)
	r, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath|evtQueryReverseDirection)
	if r == 0 {
		t.Fatalf("EvtQuery: %v", e)
	}
	res := evtHandle(r)
	defer evtClose(res)
	var ev evtHandle
	var n uint32
	if r, _, _ := procEvtNext.Call(uintptr(res), 1, uintptr(unsafe.Pointer(&ev)), 1000, 0, uintptr(unsafe.Pointer(&n))); r == 0 || n == 0 {
		return ""
	}
	defer evtClose(ev)
	s, err := evtRenderString(ev, evtRenderEventXML, buf)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return s
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}
