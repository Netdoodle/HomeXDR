//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/Netdoodle/homexdr/agent/internal/fsutil"
	"golang.org/x/sys/windows"
)

// This file is a small Windows Event Log reader that the sensors share: subscribe to a
// channel with an XPath query (pull model: a signal event plus EvtNext in batches),
// render each record as XML and parse it, and keep a bookmark on disk so an agent
// restart resumes after the last record it handled.

var (
	modwevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtSubscribe                = modwevtapi.NewProc("EvtSubscribe")
	procEvtNext                     = modwevtapi.NewProc("EvtNext")
	procEvtRender                   = modwevtapi.NewProc("EvtRender")
	procEvtClose                    = modwevtapi.NewProc("EvtClose")
	procEvtCreateBookmark           = modwevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark           = modwevtapi.NewProc("EvtUpdateBookmark")
	procEvtQuery                    = modwevtapi.NewProc("EvtQuery")
	procEvtOpenChannelConfig        = modwevtapi.NewProc("EvtOpenChannelConfig")
	procEvtGetChannelConfigProperty = modwevtapi.NewProc("EvtGetChannelConfigProperty")
)

// wevtapi constants (winevt.h).
const (
	evtSubscribeToFutureEvents     = 1
	evtSubscribeStartAfterBookmark = 3

	evtRenderEventXML = 1
	evtRenderBookmark = 2

	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200

	evtChannelConfigEnabled = 0
	evtVarTypeBoolean       = 13
)

const (
	// evtBatch is how many records one EvtNext call returns at most.
	evtBatch = 64
	// evtWait is how long the reader sleeps between checks when no signal arrives; it
	// also bounds how long a cancelled context takes to stop the reader.
	evtWait = 500 * time.Millisecond
	// bookmarkSaveInterval is how often a changed bookmark is written to disk. A crash
	// replays at most this much; a clean stop saves on the way out.
	bookmarkSaveInterval = 5 * time.Second
	// newestRecordTimeout bounds the search for the newest matching record when there is
	// no saved bookmark (a filtered reverse query can scan a large log).
	newestRecordTimeout = 5 * time.Second
	// maxRenderBuffer caps the XML buffer for one record (UTF-16 code units).
	maxRenderBuffer = 8 << 20
)

// Errors the event log reader reports for conditions callers act on.
var (
	errChannelNotFound = errors.New("channel not found")
	errAccessDenied    = errors.New("access denied")
)

// evtHandle is an EVT_HANDLE.
type evtHandle uintptr

func evtClose(h evtHandle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}

// evtError wraps a wevtapi error, mapping a missing channel and access denied to the
// errChannelNotFound and errAccessDenied sentinels.
func evtError(op, channel string, err error) error {
	switch {
	case errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND):
		return fmt.Errorf("%s %q: %w", op, channel, errChannelNotFound)
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return fmt.Errorf("%s %q: %w", op, channel, errAccessDenied)
	}
	return fmt.Errorf("%s %q: %w", op, channel, err)
}

// fatalSubscribeError reports errors that no retry with other options can fix.
func fatalSubscribeError(err error) bool {
	return errors.Is(err, errChannelNotFound) || errors.Is(err, errAccessDenied) ||
		errors.Is(err, windows.ERROR_EVT_INVALID_QUERY)
}

func evtSubscribe(channel, query string, signal windows.Handle, bookmark evtHandle, flags uint32) (evtHandle, error) {
	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	q, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return 0, err
	}
	r, _, e := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)),
		uintptr(bookmark), 0, 0, uintptr(flags))
	if r == 0 {
		return 0, evtError("subscribe to", channel, e)
	}
	return evtHandle(r), nil
}

func evtCreateBookmark(xmlText string) (evtHandle, error) {
	var p *uint16
	if xmlText != "" {
		var err error
		if p, err = windows.UTF16PtrFromString(xmlText); err != nil {
			return 0, err
		}
	}
	r, _, e := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
	if r == 0 {
		return 0, fmt.Errorf("create bookmark: %w", e)
	}
	return evtHandle(r), nil
}

func evtUpdateBookmark(bookmark, ev evtHandle) error {
	r, _, e := procEvtUpdateBookmark.Call(uintptr(bookmark), uintptr(ev))
	if r == 0 {
		return e
	}
	return nil
}

// evtRenderString renders an event (evtRenderEventXML) or bookmark (evtRenderBookmark)
// as a string, growing buf as needed.
func evtRenderString(h evtHandle, flags uint32, buf *[]uint16) (string, error) {
	if len(*buf) == 0 {
		*buf = make([]uint16, 4096)
	}
	for {
		var used, props uint32
		r, _, e := procEvtRender.Call(0, uintptr(h), uintptr(flags), uintptr(len(*buf)*2),
			uintptr(unsafe.Pointer(&(*buf)[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			n := int(used / 2)
			if n > len(*buf) {
				n = len(*buf)
			}
			return windows.UTF16ToString((*buf)[:n]), nil
		}
		if !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", e
		}
		need := int(used/2) + 1
		if need <= len(*buf) || need > maxRenderBuffer {
			return "", fmt.Errorf("render: record needs %d bytes", used)
		}
		*buf = make([]uint16, need)
	}
}

// channelEnabled reports whether a channel exists and is enabled. A missing channel
// returns errChannelNotFound.
func channelEnabled(channel string) (bool, error) {
	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return false, err
	}
	r, _, e := procEvtOpenChannelConfig.Call(0, uintptr(unsafe.Pointer(ch)), 0)
	if r == 0 {
		return false, evtError("open channel config", channel, e)
	}
	cfg := evtHandle(r)
	defer evtClose(cfg)
	// EVT_VARIANT: an 8-byte union, then Count and Type (16 bytes on every architecture).
	var v struct {
		Val   uint64
		Count uint32
		Type  uint32
	}
	var used uint32
	r, _, e = procEvtGetChannelConfigProperty.Call(uintptr(cfg), evtChannelConfigEnabled, 0,
		unsafe.Sizeof(v), uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&used)))
	if r == 0 {
		return false, evtError("read channel config", channel, e)
	}
	if v.Type != evtVarTypeBoolean {
		return false, fmt.Errorf("channel %q: unexpected Enabled type %d", channel, v.Type)
	}
	return uint32(v.Val) != 0, nil
}

// Record is one parsed event log record.
type Record struct {
	Provider    string
	EventID     uint32
	Version     uint8
	Level       uint8
	TimeCreated time.Time
	RecordID    uint64
	Channel     string
	Computer    string
	// ProcessID and ThreadID are the System/Execution attributes: the process that
	// logged the record (for Sysmon, Sysmon itself), not the process it describes.
	ProcessID, ThreadID uint32
	// UserSID is System/Security UserID, when the provider sets it.
	UserSID string
	// Data holds EventData values by Name, and the fields of a UserData element.
	Data map[string]string
	// Strings holds EventData values without a Name, in order (classic event sources
	// such as ReportEvent writers).
	Strings []string
}

// xmlEvent is the shape of an <Event> as EvtRender(EvtRenderEventXml) produces it.
type xmlEvent struct {
	System struct {
		Provider struct {
			Name            string `xml:"Name,attr"`
			EventSourceName string `xml:"EventSourceName,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Version     string `xml:"Version"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID string `xml:"EventRecordID"`
		Execution     struct {
			ProcessID string `xml:"ProcessID,attr"`
			ThreadID  string `xml:"ThreadID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData xmlUserData `xml:"UserData"`
}

// xmlUserData collects the child elements of the single element inside <UserData>.
type xmlUserData struct {
	Fields map[string]string
}

func (u *xmlUserData) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	u.Fields = map[string]string{}
	depth := 0
	var name string
	var text strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 {
				name = t.Name.Local
				text.Reset()
			}
		case xml.CharData:
			if depth == 2 {
				text.Write(t)
			}
		case xml.EndElement:
			if depth == 0 {
				return nil
			}
			if depth == 2 {
				u.Fields[name] = text.String()
			}
			depth--
		}
	}
}

// parseEventXML parses a rendered record.
func parseEventXML(s string) (*Record, error) {
	var x xmlEvent
	if err := xml.Unmarshal([]byte(s), &x); err != nil {
		// Command lines and other strings can hold control characters, which XML 1.0
		// does not allow. Replace them and try once more.
		if err2 := xml.Unmarshal([]byte(sanitizeXML(s)), &x); err2 != nil {
			return nil, fmt.Errorf("parse event XML: %w", err)
		}
	}
	sys := &x.System
	r := &Record{
		Provider: sys.Provider.Name,
		Channel:  strings.TrimSpace(sys.Channel),
		Computer: strings.TrimSpace(sys.Computer),
		UserSID:  sys.Security.UserID,
		Data:     map[string]string{},
	}
	if r.Provider == "" {
		r.Provider = sys.Provider.EventSourceName
	}
	if v, err := strconv.ParseUint(strings.TrimSpace(sys.EventID), 10, 32); err == nil {
		r.EventID = uint32(v)
	}
	if v, err := strconv.ParseUint(strings.TrimSpace(sys.Version), 10, 8); err == nil {
		r.Version = uint8(v)
	}
	if v, err := strconv.ParseUint(strings.TrimSpace(sys.Level), 10, 8); err == nil {
		r.Level = uint8(v)
	}
	if v, err := strconv.ParseUint(strings.TrimSpace(sys.EventRecordID), 10, 64); err == nil {
		r.RecordID = v
	}
	if v, err := strconv.ParseUint(sys.Execution.ProcessID, 10, 32); err == nil {
		r.ProcessID = uint32(v)
	}
	if v, err := strconv.ParseUint(sys.Execution.ThreadID, 10, 32); err == nil {
		r.ThreadID = uint32(v)
	}
	if t, err := time.Parse(time.RFC3339Nano, sys.TimeCreated.SystemTime); err == nil {
		r.TimeCreated = t.UTC()
	}
	for _, d := range x.EventData.Data {
		if d.Name != "" {
			r.Data[d.Name] = d.Value
		} else {
			r.Strings = append(r.Strings, d.Value)
		}
	}
	for k, v := range x.UserData.Fields {
		if _, dup := r.Data[k]; !dup {
			r.Data[k] = v
		}
	}
	return r, nil
}

var badCharRef = regexp.MustCompile(`&#(x[0-9a-fA-F]+|[0-9]+);`)

// sanitizeXML replaces characters and character references that XML 1.0 forbids with
// U+FFFD.
func sanitizeXML(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t', r == '\n', r == '\r':
			return r
		case r < 0x20, r == 0xFFFE, r == 0xFFFF:
			return utf8.RuneError
		}
		return r
	}, s)
	return badCharRef.ReplaceAllStringFunc(s, func(m string) string {
		num := m[2 : len(m)-1]
		var v uint64
		var err error
		if num[0] == 'x' {
			v, err = strconv.ParseUint(num[1:], 16, 32)
		} else {
			v, err = strconv.ParseUint(num, 10, 32)
		}
		if err != nil || (v < 0x20 && v != '\t' && v != '\n' && v != '\r') || v == 0xFFFE || v == 0xFFFF || v > 0x10FFFF {
			return string(utf8.RuneError)
		}
		return m
	})
}

// subscribeOptions configures a subscription.
type subscribeOptions struct {
	Channel string
	// Query is an XPath filter such as "*[System[(EventID=1 or EventID=5)]]"; empty
	// means every record.
	Query string
	// BookmarkFile is where the position is persisted; empty disables bookmarks, and
	// the subscription then starts at new records.
	BookmarkFile string
	Log          *slog.Logger
}

// subscription reads one channel.
type subscription struct {
	opts     subscribeOptions
	signal   windows.Handle
	h        evtHandle
	bookmark evtHandle
	// resumed is true when the subscription started after a saved bookmark.
	resumed  bool
	dirty    bool
	lastSave time.Time
	buf      []uint16
	// renderErrs counts records that could not be rendered or parsed.
	renderErrs uint64
	lastErrLog time.Time
}

// subscribe opens a subscription. It resumes after the saved bookmark when there is a
// usable one; otherwise it starts at new records and points the bookmark at the newest
// matching record already in the log, so a restart before the first new record does
// not skip anything. A missing channel returns errChannelNotFound and missing rights
// errAccessDenied.
func subscribe(opts subscribeOptions) (*subscription, error) {
	if opts.Query == "" {
		opts.Query = "*"
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	sig, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return nil, fmt.Errorf("create event: %w", err)
	}
	s := &subscription{opts: opts, signal: sig}
	if err := s.open(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// open (re)creates the subscription handle from the in-memory or saved bookmark.
func (s *subscription) open() error {
	ch, q := s.opts.Channel, s.opts.Query
	if s.opts.BookmarkFile != "" {
		if s.bookmark == 0 {
			s.bookmark = s.loadBookmark()
			s.resumed = s.bookmark != 0
		}
		if s.bookmark != 0 {
			h, err := evtSubscribe(ch, q, s.signal, s.bookmark, evtSubscribeStartAfterBookmark)
			if err == nil {
				s.h = h
				return nil
			}
			if fatalSubscribeError(err) {
				return err
			}
			s.opts.Log.Warn("event log: saved position not usable, starting at new records", "channel", ch, "err", err)
			evtClose(s.bookmark)
			s.bookmark, s.resumed = 0, false
		}
		bm, err := evtCreateBookmark("")
		if err != nil {
			return err
		}
		s.bookmark = bm
		found, err := s.markNewest()
		if err != nil && fatalSubscribeError(err) {
			return err
		}
		if found {
			h, err := evtSubscribe(ch, q, s.signal, s.bookmark, evtSubscribeStartAfterBookmark)
			if err == nil {
				s.h = h
				s.dirty = true
				s.saveBookmark()
				return nil
			}
			if fatalSubscribeError(err) {
				return err
			}
		}
	}
	h, err := evtSubscribe(ch, q, s.signal, 0, evtSubscribeToFutureEvents)
	if err != nil {
		return err
	}
	s.h = h
	return nil
}

// markNewest points the bookmark at the newest record matching the query, if any.
func (s *subscription) markNewest() (bool, error) {
	ch, err := windows.UTF16PtrFromString(s.opts.Channel)
	if err != nil {
		return false, err
	}
	q, err := windows.UTF16PtrFromString(s.opts.Query)
	if err != nil {
		return false, err
	}
	r, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath|evtQueryReverseDirection)
	if r == 0 {
		return false, evtError("query", s.opts.Channel, e)
	}
	res := evtHandle(r)
	defer evtClose(res)
	var ev evtHandle
	var n uint32
	r, _, e = procEvtNext.Call(uintptr(res), 1, uintptr(unsafe.Pointer(&ev)), uintptr(newestRecordTimeout/time.Millisecond), 0, uintptr(unsafe.Pointer(&n)))
	if r == 0 || n == 0 {
		if errors.Is(e, windows.ERROR_NO_MORE_ITEMS) || errors.Is(e, windows.ERROR_TIMEOUT) {
			return false, nil
		}
		return false, evtError("query", s.opts.Channel, e)
	}
	defer evtClose(ev)
	if err := evtUpdateBookmark(s.bookmark, ev); err != nil {
		return false, err
	}
	return true, nil
}

func (s *subscription) loadBookmark() evtHandle {
	b, err := os.ReadFile(s.opts.BookmarkFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.opts.Log.Warn("event log: cannot read saved position", "file", s.opts.BookmarkFile, "err", err)
		}
		return 0
	}
	text := strings.TrimSpace(string(b))
	if !strings.Contains(text, "<Bookmark ") {
		return 0 // empty or not a bookmark
	}
	bm, err := evtCreateBookmark(text)
	if err != nil {
		s.opts.Log.Warn("event log: saved position is invalid, starting at new records", "file", s.opts.BookmarkFile, "err", err)
		return 0
	}
	return bm
}

// saveBookmark writes a changed bookmark to disk.
func (s *subscription) saveBookmark() {
	if !s.dirty || s.bookmark == 0 || s.opts.BookmarkFile == "" {
		return
	}
	text, err := evtRenderString(s.bookmark, evtRenderBookmark, &s.buf)
	if err == nil {
		if err = os.MkdirAll(filepath.Dir(s.opts.BookmarkFile), 0o700); err == nil {
			err = fsutil.WriteFileAtomic(s.opts.BookmarkFile, []byte(text+"\n"), 0o600)
		}
	}
	if err != nil {
		s.opts.Log.Warn("event log: cannot save position", "file", s.opts.BookmarkFile, "err", err)
		return
	}
	s.dirty = false
	s.lastSave = time.Now()
}

// run calls fn for every record until ctx is cancelled, then saves the bookmark. fn
// runs on the reader's goroutine and must return quickly.
func (s *subscription) run(ctx context.Context, fn func(*Record)) error {
	defer s.saveBookmark()
	handles := make([]evtHandle, evtBatch)
	for {
		if ctx.Err() != nil {
			return nil
		}
		w, err := windows.WaitForSingleObject(s.signal, uint32(evtWait/time.Millisecond))
		if err != nil {
			return fmt.Errorf("event log wait: %w", err)
		}
		if w == windows.WAIT_OBJECT_0 {
			// Reset before reading, so a record that arrives while we read sets it again.
			_ = windows.ResetEvent(s.signal)
		}
		// Read on timeouts too: it costs one call and covers a missed signal.
		if err := s.drain(ctx, handles, fn); err != nil {
			return err
		}
		if s.dirty && time.Since(s.lastSave) >= bookmarkSaveInterval {
			s.saveBookmark()
		}
	}
}

func (s *subscription) drain(ctx context.Context, handles []evtHandle, fn func(*Record)) error {
	for {
		var n uint32
		r, _, e := procEvtNext.Call(uintptr(s.h), uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), 0, 0, uintptr(unsafe.Pointer(&n)))
		if r == 0 {
			switch {
			case errors.Is(e, windows.ERROR_NO_MORE_ITEMS), errors.Is(e, windows.ERROR_TIMEOUT):
				return nil
			case errors.Is(e, windows.ERROR_EVT_QUERY_RESULT_STALE), errors.Is(e, windows.ERROR_EVT_QUERY_RESULT_INVALID_POSITION):
				// The log was cleared or wrapped past our position: subscribe again
				// from the bookmark.
				s.opts.Log.Warn("event log: position lost, resubscribing", "channel", s.opts.Channel, "err", e)
				evtClose(s.h)
				s.h = 0
				return s.open()
			}
			return evtError("read", s.opts.Channel, e)
		}
		for _, h := range handles[:n] {
			s.handle(h, fn)
			evtClose(h)
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func (s *subscription) handle(h evtHandle, fn func(*Record)) {
	text, err := evtRenderString(h, evtRenderEventXML, &s.buf)
	var rec *Record
	if err == nil {
		rec, err = parseEventXML(text)
	}
	if err != nil {
		s.renderErrs++
		if time.Since(s.lastErrLog) > time.Minute {
			s.lastErrLog = time.Now()
			s.opts.Log.Warn("event log: cannot read record", "channel", s.opts.Channel, "err", err, "total", s.renderErrs)
		}
	} else {
		fn(rec)
	}
	if s.bookmark != 0 && evtUpdateBookmark(s.bookmark, h) == nil {
		s.dirty = true
	}
}

// Close saves the bookmark and releases the subscription.
func (s *subscription) Close() {
	s.saveBookmark()
	evtClose(s.h)
	s.h = 0
	evtClose(s.bookmark)
	s.bookmark = 0
	if s.signal != 0 {
		windows.CloseHandle(s.signal)
		s.signal = 0
	}
}

// bookmarkFile returns the bookmark path for one sensor's subscription to a channel.
func bookmarkFile(dataDir, sensor, channel string) string {
	if dataDir == "" {
		return ""
	}
	var b bytes.Buffer
	for _, r := range strings.ToLower(channel) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return filepath.Join(dataDir, "eventlog", sensor+"-"+b.String()+".bookmark")
}
