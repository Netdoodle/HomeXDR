package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// fakeS3 is an in-memory, path-style S3 with multipart uploads and ListObjectsV2.
type fakeS3 struct {
	mu      sync.Mutex
	objs    map[string][]byte
	uploads map[string]map[int][]byte
	classes map[string]string
	n       int
}

func newFakeS3(t *testing.T) (*fakeS3, *httptest.Server) {
	f := &fakeS3{objs: map[string][]byte{}, uploads: map[string]map[int][]byte{}, classes: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeS3) serve(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKID/") || r.Header.Get("x-amz-content-sha256") == "" {
		w.WriteHeader(403)
		fmt.Fprint(w, "<Error><Code>AccessDenied</Code><Message>unsigned</Message></Error>")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/bkt")
	key := strings.TrimPrefix(path, "/")
	q := r.URL.Query()
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodGet && key == "":
		var keys []string
		for k := range f.objs {
			if strings.HasPrefix(k, q.Get("prefix")) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		fmt.Fprint(w, "<ListBucketResult>")
		for _, k := range keys {
			fmt.Fprintf(w, "<Contents><Key>%s</Key></Contents>", k)
		}
		fmt.Fprint(w, "<IsTruncated>false</IsTruncated></ListBucketResult>")
	case r.Method == http.MethodPost && q.Has("uploads"):
		f.n++
		id := fmt.Sprint("up", f.n)
		f.uploads[id] = map[int][]byte{}
		f.classes[key] = r.Header.Get("x-amz-storage-class")
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", id)
	case r.Method == http.MethodPut && q.Get("uploadId") != "":
		var num int
		fmt.Sscan(q.Get("partNumber"), &num)
		f.uploads[q.Get("uploadId")][num] = body
		w.Header().Set("ETag", fmt.Sprintf(`"etag%d"`, num))
	case r.Method == http.MethodPost && q.Get("uploadId") != "":
		parts := f.uploads[q.Get("uploadId")]
		var buf bytes.Buffer
		for i := 1; i <= len(parts); i++ {
			buf.Write(parts[i])
		}
		f.objs[key] = buf.Bytes()
		fmt.Fprint(w, "<CompleteMultipartUploadResult/>")
	case r.Method == http.MethodDelete && q.Get("uploadId") != "":
		delete(f.uploads, q.Get("uploadId"))
		w.WriteHeader(204)
	case r.Method == http.MethodPut:
		f.objs[key] = body
	case r.Method == http.MethodGet:
		b, ok := f.objs[key]
		if !ok {
			w.WriteHeader(404)
			fmt.Fprint(w, "<Error><Code>NoSuchKey</Code><Message>no</Message></Error>")
			return
		}
		w.Write(b)
	case r.Method == http.MethodDelete:
		delete(f.objs, key)
		w.WriteHeader(204)
	}
}

type fakeStore struct {
	mu      sync.Mutex
	days    map[string][]string // day -> raw events
	modules map[string]string   // raw -> module
	got     []*event.Event
}

func (s *fakeStore) usage(context.Context) (*events.Usage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := &events.Usage{}
	var keys []string
	for d := range s.days {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	for _, d := range keys {
		t, _ := time.Parse("2006-01-02", d)
		u.Days = append(u.Days, events.DayUsage{Day: t, Bytes: int64(len(s.days[d]) * 100), Events: int64(len(s.days[d]))})
	}
	return u, nil
}

func (s *fakeStore) export(_ context.Context, from, _ time.Time, skip []string, fn func(string) error) (int64, error) {
	s.mu.Lock()
	raws := append([]string(nil), s.days[from.Format("2006-01-02")]...)
	s.mu.Unlock()
	var n int64
	for _, r := range raws {
		skipIt := false
		for _, m := range skip {
			if s.modules[r] == m {
				skipIt = true
			}
		}
		if skipIt {
			continue
		}
		if err := fn(r); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *fakeStore) insert(_ context.Context, evs []*event.Event) error {
	s.mu.Lock()
	s.got = append(s.got, evs...)
	s.mu.Unlock()
	return nil
}

func TestArchiveAndImport(t *testing.T) {
	f, srv := newFakeS3(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	fs := &fakeStore{days: map[string][]string{}, modules: map[string]string{}}
	for d := 7; d <= 9; d++ {
		day := fmt.Sprintf("2026-11-%02d", d)
		start := time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 50; i++ {
			mod := "eventlog"
			if i%10 == 0 {
				mod = "netflow"
			}
			b, _ := json.Marshal(event.Event{ID: fmt.Sprintf("%s-%d", day, i), Timestamp: start.Add(time.Duration(i) * 29 * time.Minute),
				Message: strings.Repeat("x", 100), Event: event.Meta{Module: mod}})
			fs.days[day] = append(fs.days[day], string(b))
			fs.modules[string(b)] = mod
		}
	}
	s := New(Deps{State: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Usage: fs.usage, Export: fs.export, Insert: fs.insert})
	s.now = func() time.Time { return now }
	ctx := context.Background()

	in := Input{Settings: Settings{Enabled: true, Endpoint: srv.URL, Bucket: "bkt", Prefix: "/homelab/", AccessKeyID: "AKID", Secret: "shh",
		PathStyle: true, StorageClass: "GLACIER_IR", SkipModules: []string{"NetFlow"}, Backfill: true, RunHour: 0}}
	if err := s.Test(ctx, in); err != nil {
		t.Fatalf("test: %v", err)
	}
	v, err := s.Save(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if v.Secret != "" || !v.SecretSet || len(v.Pending) != 2 {
		t.Fatalf("view after save: %+v", v)
	}
	s.runOnce(ctx, true)
	v = s.View(ctx)
	if v.ArchivedDays != 2 || len(v.Pending) != 0 || v.LastError != "" {
		t.Fatalf("after run: %+v", v)
	}
	key := "homelab/events/2026/11/08/homexdr-events-20261108.ndjson.zst"
	if _, ok := f.objs[key]; !ok {
		t.Fatalf("archive missing; objects: %v", keysOf(f.objs))
	}
	if _, ok := f.objs[key+".manifest.json"]; !ok || f.classes[key] != "GLACIER_IR" {
		t.Fatalf("manifest or storage class: class %q", f.classes[key])
	}
	if r := v.Recent[0]; r.Day != "2026-11-08" || r.Events != 45 {
		t.Fatalf("record = %+v (netflow skipped: want 45)", r)
	}
	// Today (Nov 9) is never archived.
	if _, ok := f.objs["homelab/events/2026/11/09/homexdr-events-20261109.ndjson.zst"]; ok {
		t.Fatal("today was archived")
	}

	// The archives are listed; a day still in the store cannot be imported.
	list, err := s.Archived(ctx)
	if err != nil || len(list) != 2 || list[0].Day != "2026-11-08" || !list[0].InStore {
		t.Fatalf("archived = %+v, %v", list, err)
	}
	if err := s.Import(ctx, "2026-11-08"); err == nil {
		t.Fatal("import of a day still in the store accepted")
	}
	// After retention removes it, it comes back with its events intact.
	fs.mu.Lock()
	delete(fs.days, "2026-11-07")
	fs.mu.Unlock()
	if err := s.Import(ctx, "2026-11-07"); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		s.mu.Lock()
		busy := s.busy
		s.mu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("import did not finish")
		}
	}
	if len(fs.got) != 45 || fs.got[0].ID == "" || !strings.HasPrefix(fs.got[0].ID, "2026-11-07-") {
		t.Fatalf("imported %d events, first %+v", len(fs.got), fs.got[0])
	}
	// An empty secret keeps the saved one; clear_secret removes it.
	in.Secret = ""
	if v, err := s.Save(ctx, in); err != nil || !v.SecretSet {
		t.Fatalf("keep secret: %+v %v", v, err)
	}
}

func TestSettingsValidation(t *testing.T) {
	for _, in := range []Input{
		{Settings: Settings{Enabled: true, Endpoint: "s3.amazonaws.com", Bucket: "bkt", AccessKeyID: "a", Secret: "b"}},
		{Settings: Settings{Enabled: true, Endpoint: "https://s3.amazonaws.com", Bucket: "Bad_Bucket", AccessKeyID: "a", Secret: "b"}},
		{Settings: Settings{Enabled: true, Endpoint: "https://s3.amazonaws.com", Bucket: "bkt"}},
		{Settings: Settings{RunHour: 24}},
		{Settings: Settings{Enabled: true, Endpoint: "http://s3.example.com", Bucket: "bkt", AccessKeyID: "a", Secret: "b"}},
		{Settings: Settings{Enabled: true, Endpoint: "http://203.0.113.9:9000", Bucket: "bkt", AccessKeyID: "a", Secret: "b"}},
	} {
		if _, err := in.normalize(Settings{}); err == nil {
			t.Errorf("%+v accepted", in.Settings)
		}
	}
	// Plain http stays possible for a store on this host or a private network.
	for _, ep := range []string{"http://127.0.0.1:9000", "http://192.168.120.20:9000", "http://localhost:9000", "http://[fd00::5]:9000"} {
		in := Input{Settings: Settings{Enabled: true, Endpoint: ep, Bucket: "bkt", AccessKeyID: "a", Secret: "b"}}
		if _, err := in.normalize(Settings{}); err != nil {
			t.Errorf("%s: %v", ep, err)
		}
	}
}

func TestSigV4KnownVector(t *testing.T) {
	// AWS documentation example: GET /test.txt from examplebucket with a Range header is
	// not reproducible here, so check the stable parts: scope and signed headers.
	c := &S3{Endpoint: "https://s3.amazonaws.com", Region: "us-east-1", Bucket: "examplebucket", AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", now: func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }}
	var got string
	c.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		got = r.Header.Get("Authorization")
		if r.URL.Host != "examplebucket.s3.amazonaws.com" || r.URL.EscapedPath() != "/a%20b/test.txt" {
			t.Errorf("url = %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}
	if err := c.Put(context.Background(), "a b/test.txt", "text/plain", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=") {
		t.Fatalf("authorization = %s", got)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func keysOf(m map[string][]byte) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

// TestSigV4AWSExample signs AWS's documented "PUT Object" example and expects its
// published signature.
func TestSigV4AWSExample(t *testing.T) {
	c := &S3{Endpoint: "https://s3.amazonaws.com", Region: "us-east-1", Bucket: "examplebucket", AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", now: func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }}
	var got string
	c.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		got = r.Header.Get("Authorization")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}
	resp, err := c.do(context.Background(), http.MethodPut, "test$file.text", nil, []byte("Welcome to Amazon S3."),
		map[string]string{"Date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class": "REDUCED_REDUNDANCY"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
	if got != want {
		t.Fatalf("authorization\n got %s\nwant %s", got, want)
	}
}

const importDay7 = "2026-11-07"

var importKey7 = "homelab/events/2026/11/07/homexdr-events-20261107.ndjson.zst"

func testEvent(id string, ts time.Time) string {
	b, _ := json.Marshal(event.Event{ID: id, Timestamp: ts, Message: "m", Event: event.Meta{Module: "eventlog"}})
	return string(b)
}

// importSetup archives 2026-11-07 and 2026-11-08 (45 events each) into a fake bucket and
// drops 2026-11-07 from the store, so it can be imported.
func importSetup(t *testing.T) (*fakeS3, *fakeStore, *Service) {
	t.Helper()
	f, srv := newFakeS3(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fs := &fakeStore{days: map[string][]string{}, modules: map[string]string{}}
	for d := 7; d <= 9; d++ {
		start := time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 45; i++ {
			day := start.Format("2006-01-02")
			fs.days[day] = append(fs.days[day], testEvent(fmt.Sprintf("%s-%d", day, i), start.Add(time.Duration(i)*30*time.Minute)))
		}
	}
	s := New(Deps{State: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Usage: fs.usage, Export: fs.export, Insert: fs.insert})
	s.now = func() time.Time { return time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC) }
	ctx := context.Background()
	in := Input{Settings: Settings{Enabled: true, Endpoint: srv.URL, Bucket: "bkt", Prefix: "homelab", AccessKeyID: "AKID", Secret: "shh",
		PathStyle: true, Backfill: true}}
	if _, err := s.Save(ctx, in); err != nil {
		t.Fatal(err)
	}
	s.runOnce(ctx, true)
	if v := s.View(ctx); v.ArchivedDays != 2 || v.LastError != "" {
		t.Fatalf("after run: %+v", v)
	}
	fs.mu.Lock()
	delete(fs.days, importDay7)
	fs.mu.Unlock()
	return f, fs, s
}

// runImport imports a day, waits for it and returns the import error ("" on success).
func runImport(t *testing.T, s *Service, day string) string {
	t.Helper()
	s.mu.Lock()
	s.st.LastError = ""
	s.mu.Unlock()
	if err := s.Import(context.Background(), day); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		busy, msg := s.busy, s.st.LastError
		s.mu.Unlock()
		if !busy {
			return msg
		}
		if time.Now().After(deadline) {
			t.Fatal("import did not finish")
		}
	}
}

func (f *fakeS3) edit(key string, fn func([]byte) []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fn == nil {
		delete(f.objs, key)
		return
	}
	f.objs[key] = fn(append([]byte(nil), f.objs[key]...))
}

func (s *fakeStore) inserted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

// putArchive replaces the 2026-11-07 archive with lines and records its true hash, size
// and event count locally, as archiveDay would have.
func putArchive(t *testing.T, f *fakeS3, s *Service, lines []string) {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		io.WriteString(zw, l+"\n")
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.edit(importKey7, func([]byte) []byte { return buf.Bytes() })
	sum := sha256.Sum256(buf.Bytes())
	s.mu.Lock()
	s.st.Days[importDay7] = DayRecord{Day: importDay7, Key: importKey7, Events: int64(len(lines)), Bytes: int64(buf.Len()), SHA256: hex.EncodeToString(sum[:])}
	s.mu.Unlock()
}

func TestImportRejectsTamperedArchive(t *testing.T) {
	for name, tamper := range map[string]func([]byte) []byte{
		"flipped byte": func(b []byte) []byte { b[len(b)/2] ^= 0x01; return b },
		"appended":     func(b []byte) []byte { return append(b, 0) },
		"truncated":    func(b []byte) []byte { return b[:len(b)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			f, fs, s := importSetup(t)
			f.edit(importKey7, tamper)
			msg := runImport(t, s, importDay7)
			if !strings.Contains(msg, "tampered") || fs.inserted() != 0 {
				t.Fatalf("error %q, %d inserted", msg, fs.inserted())
			}
		})
	}
}

func TestImportRejectsBadEvents(t *testing.T) {
	day := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	// More than one insert batch of good events, so a late bad line would have left a
	// partial import behind.
	good := make([]string, 0, 2*importBatch+10)
	for i := 0; i < cap(good); i++ {
		good = append(good, testEvent(fmt.Sprint("ok-", i), day.Add(time.Duration(i)*time.Second)))
	}
	with := func(last ...string) []string { return append(append([]string(nil), good...), last...) }
	for _, tc := range []struct {
		name    string
		lines   []string
		events  int64 // recorded count; 0 keeps the true count
		wantErr string
	}{
		{"day boundaries", with(testEvent("first", day), testEvent("last", day.Add(24*time.Hour-time.Nanosecond))), 0, ""},
		{"next midnight", with(testEvent("late", day.Add(24*time.Hour))), 0, "outside 2026-11-07"},
		{"day before", with(testEvent("early", day.Add(-time.Millisecond))), 0, "outside 2026-11-07"},
		{"no timestamp", with(`{"id":"none"}`), 0, "outside 2026-11-07"},
		{"other zone", with(`{"id":"tz","@timestamp":"2026-11-07T23:30:00-02:00"}`), 0, "outside 2026-11-07"},
		{"bad json", with(`{"id":`), 0, "line 4011"},
		{"more than recorded", good, int64(len(good) - 1), "more than the 4009 events recorded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, fs, s := importSetup(t)
			putArchive(t, f, s, tc.lines)
			if tc.events != 0 {
				s.mu.Lock()
				r := s.st.Days[importDay7]
				r.Events = tc.events
				s.st.Days[importDay7] = r
				s.mu.Unlock()
			}
			msg := runImport(t, s, importDay7)
			if tc.wantErr == "" {
				if msg != "" || fs.inserted() != len(tc.lines) {
					t.Fatalf("error %q, %d of %d inserted", msg, fs.inserted(), len(tc.lines))
				}
				return
			}
			if !strings.Contains(msg, tc.wantErr) || fs.inserted() != 0 {
				t.Fatalf("error %q (want %q), %d inserted", msg, tc.wantErr, fs.inserted())
			}
		})
	}
}

func TestImportSizeCaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    *int64
		max  int64
	}{{"decompressed", &maxImportDecompressed, 1000}, {"archive", &maxImportArchive, 50}} {
		v := tc.v
		t.Run(tc.name, func(t *testing.T) {
			_, fs, s := importSetup(t)
			old := *v
			*v = tc.max
			t.Cleanup(func() { *v = old })
			msg := runImport(t, s, importDay7)
			if !strings.Contains(msg, "import limit") || fs.inserted() != 0 {
				t.Fatalf("error %q, %d inserted", msg, fs.inserted())
			}
		})
	}
}

func TestImportFallsBackToManifest(t *testing.T) {
	f, fs, s := importSetup(t)
	s.mu.Lock()
	delete(s.st.Days, importDay7) // a reinstalled server
	s.mu.Unlock()
	if msg := runImport(t, s, importDay7); msg != "" || fs.inserted() != 45 {
		t.Fatalf("error %q, %d inserted", msg, fs.inserted())
	}
	// The manifest's hash is still checked.
	fs.mu.Lock()
	fs.got = nil
	fs.mu.Unlock()
	f.edit(importKey7, func(b []byte) []byte { b[len(b)/2] ^= 0x01; return b })
	if msg := runImport(t, s, importDay7); !strings.Contains(msg, "does not match the manifest") || fs.inserted() != 0 {
		t.Fatalf("error %q, %d inserted", msg, fs.inserted())
	}
}

func TestImportRefusedWithoutRecordOrManifest(t *testing.T) {
	for name, manifest := range map[string]func([]byte) []byte{
		"missing": nil,
		"invalid": func([]byte) []byte {
			return []byte(`{"format":"homexdr-events-v1","day":"2026-11-07","sha256":"nothex"}`)
		},
		"wrong day": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"day": "2026-11-07"`), []byte(`"day": "2026-11-08"`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, fs, s := importSetup(t)
			s.mu.Lock()
			delete(s.st.Days, importDay7)
			s.mu.Unlock()
			f.edit(importKey7+".manifest.json", manifest)
			msg := runImport(t, s, importDay7)
			if !strings.Contains(msg, "cannot be verified") || fs.inserted() != 0 {
				t.Fatalf("error %q, %d inserted", msg, fs.inserted())
			}
		})
	}
}
