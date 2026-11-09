// Package backup copies events to S3-compatible object storage as cold archives and
// brings archived days back.
//
// Archives are not searchable where they are: each completed UTC day becomes one
// zstd-compressed file of newline-delimited event JSON, plus a small manifest. To look
// at an archived day again, import it: its events go back into the event store as they
// were (without running detection rules on them again).
package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	settingsKey = "backup_settings"
	stateKey    = "backup_state"
	// Format names the archive layout, written to each manifest.
	Format = "homexdr-events-v1"
)

// Settings are stored in the kv table. Secret is write-only.
type Settings struct {
	Enabled      bool     `json:"enabled"`
	Provider     string   `json:"provider"` // aws, b2, wasabi, r2, minio, other: console presets only
	Endpoint     string   `json:"endpoint"`
	Region       string   `json:"region"`
	Bucket       string   `json:"bucket"`
	Prefix       string   `json:"prefix"`
	AccessKeyID  string   `json:"access_key_id"`
	Secret       string   `json:"secret,omitempty"`
	PathStyle    bool     `json:"path_style"`
	StorageClass string   `json:"storage_class"`
	SkipModules  []string `json:"skip_modules"`
	// Backfill also archives the days stored before backups were turned on.
	Backfill bool `json:"backfill"`
	// RunHour is the local hour after which the previous days are archived.
	RunHour      int        `json:"run_hour"`
	EnabledSince *time.Time `json:"enabled_since,omitempty"`
}

// Input is what the console sends: an empty Secret keeps the saved one.
type Input struct {
	Settings
	ClearSecret bool `json:"clear_secret"`
}

// DayRecord is one archived day.
type DayRecord struct {
	Day        string    `json:"day"` // 2006-01-02 (UTC)
	Key        string    `json:"key"`
	Events     int64     `json:"events"`
	Bytes      int64     `json:"bytes"` // compressed
	SHA256     string    `json:"sha256"`
	UploadedAt time.Time `json:"uploaded_at"`
}

type state struct {
	Days        map[string]DayRecord `json:"days"`
	LastRun     *time.Time           `json:"last_run,omitempty"`
	LastSuccess *time.Time           `json:"last_success,omitempty"`
	LastError   string               `json:"last_error,omitempty"`
}

// Deps connect the service to the event store.
type Deps struct {
	State  *store.Store
	Log    *slog.Logger
	Usage  func(ctx context.Context) (*events.Usage, error)
	Export func(ctx context.Context, from, to time.Time, skip []string, fn func(string) error) (int64, error)
	// Insert stores imported events as they are (no detection).
	Insert func(ctx context.Context, evs []*event.Event) error
}

// Service runs the archives.
type Service struct {
	d   Deps
	mu  sync.Mutex
	set Settings
	st  state
	// activity is what runs now, for the status ("archiving 2026-11-08", ...).
	activity string
	busy     bool
	kick     chan struct{}
	now      func() time.Time
}

// InputError is a bad setting.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

// New returns the service; call Load.
func New(d Deps) *Service {
	return &Service{d: d, set: Settings{RunHour: 3}, st: state{Days: map[string]DayRecord{}}, kick: make(chan struct{}, 1), now: time.Now}
}

// Load reads settings and state.
func (s *Service) Load(ctx context.Context) error {
	var set Settings
	if err := s.d.State.GetKV(ctx, settingsKey, &set); err == nil {
		s.set = set
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	var st state
	if err := s.d.State.GetKV(ctx, stateKey, &st); err == nil {
		if st.Days == nil {
			st.Days = map[string]DayRecord{}
		}
		s.st = st
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func (s *Service) saveState(ctx context.Context) {
	s.mu.Lock()
	st := s.st
	days := make(map[string]DayRecord, len(st.Days))
	for k, v := range st.Days {
		days[k] = v
	}
	st.Days = days
	s.mu.Unlock()
	if err := s.d.State.SetKV(ctx, stateKey, st); err != nil {
		s.d.Log.Error("save backup state", "err", err)
	}
}

var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

func (in Input) normalize(old Settings) (Settings, error) {
	set := in.Settings
	set.Endpoint = strings.TrimRight(strings.TrimSpace(set.Endpoint), "/")
	set.Bucket = strings.TrimSpace(set.Bucket)
	set.Region = strings.TrimSpace(set.Region)
	set.Prefix = strings.Trim(strings.TrimSpace(set.Prefix), "/")
	set.AccessKeyID = strings.TrimSpace(set.AccessKeyID)
	switch {
	case in.ClearSecret:
		set.Secret = ""
	case set.Secret == "":
		set.Secret = old.Secret
	}
	if set.Region == "" {
		set.Region = "us-east-1"
	}
	if set.RunHour < 0 || set.RunHour > 23 {
		return set, &InputError{"run hour must be 0-23"}
	}
	var mods []string
	for _, m := range set.SkipModules {
		if m = strings.ToLower(strings.TrimSpace(m)); m != "" {
			mods = append(mods, m)
		}
	}
	set.SkipModules = mods
	set.EnabledSince = old.EnabledSince
	if set.Enabled {
		if !strings.HasPrefix(set.Endpoint, "https://") && !strings.HasPrefix(set.Endpoint, "http://") {
			return set, &InputError{"endpoint must start with https:// (for example https://s3.us-east-1.amazonaws.com)"}
		}
		if !bucketRe.MatchString(set.Bucket) {
			return set, &InputError{"bucket name: 3-63 lowercase letters, digits, dots and hyphens"}
		}
		if set.AccessKeyID == "" || set.Secret == "" {
			return set, &InputError{"enter the access key ID and secret key"}
		}
		if !old.Enabled || set.EnabledSince == nil {
			t := time.Now().UTC()
			set.EnabledSince = &t
		}
	}
	return set, nil
}

// Save validates and stores settings.
func (s *Service) Save(ctx context.Context, in Input) (View, error) {
	s.mu.Lock()
	old := s.set
	s.mu.Unlock()
	set, err := in.normalize(old)
	if err != nil {
		return View{}, err
	}
	if err := s.d.State.SetKV(ctx, settingsKey, set); err != nil {
		return View{}, err
	}
	s.mu.Lock()
	s.set = set
	s.mu.Unlock()
	s.Kick()
	return s.View(ctx), nil
}

func (set Settings) client() *S3 {
	return &S3{Endpoint: set.Endpoint, Region: set.Region, Bucket: set.Bucket, AccessKey: set.AccessKeyID,
		SecretKey: set.Secret, PathStyle: set.PathStyle, StorageClass: set.StorageClass}
}

func (set Settings) prefix() string {
	if set.Prefix == "" {
		return "events/"
	}
	return set.Prefix + "/events/"
}

func (set Settings) dayKey(day time.Time) string {
	return set.prefix() + day.Format("2006/01/02") + "/homexdr-events-" + day.Format("20060102") + ".ndjson.zst"
}

// Test writes, reads back and deletes a small object with the given settings (or the
// saved ones for fields left empty).
func (s *Service) Test(ctx context.Context, in Input) error {
	s.mu.Lock()
	old := s.set
	s.mu.Unlock()
	in.Enabled = true
	set, err := in.normalize(old)
	if err != nil {
		return err
	}
	c := set.client()
	c.StorageClass = "" // a test object needs no archive class
	key := set.prefix() + ".homexdr-test-" + fmt.Sprint(time.Now().UnixNano())
	if err := c.Put(ctx, key, "text/plain", []byte("HomeXDR backup test object; safe to delete.\n")); err != nil {
		return fmt.Errorf("write a test object: %w", err)
	}
	r, err := c.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("read the test object back: %w", err)
	}
	r.Close()
	if err := c.Delete(ctx, key); err != nil {
		return fmt.Errorf("delete the test object (the key needs delete rights to clean up after tests): %w", err)
	}
	return nil
}

// Kick asks the loop to look for work now.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run archives completed days until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		s.runOnce(ctx, false)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
	}
}

// RunNow archives every pending day now, regardless of the run hour.
func (s *Service) RunNow() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.set.Enabled {
		return &InputError{"backups are turned off"}
	}
	if s.busy {
		return &InputError{"a backup or import is already running"}
	}
	go s.runOnce(context.Background(), true)
	return nil
}

// pending lists completed days stored locally that are not archived yet, oldest first.
func (s *Service) pending(ctx context.Context) ([]events.DayUsage, error) {
	u, err := s.d.Usage(ctx)
	if err != nil {
		return nil, err
	}
	today := s.now().UTC().Truncate(24 * time.Hour)
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []events.DayUsage
	for _, d := range u.Days {
		if !d.Day.Before(today) {
			continue
		}
		if _, done := s.st.Days[d.Day.Format("2006-01-02")]; done {
			continue
		}
		if !s.set.Backfill && s.set.EnabledSince != nil && d.Day.Before(s.set.EnabledSince.Truncate(24*time.Hour).AddDate(0, 0, -1)) {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

func (s *Service) runOnce(ctx context.Context, force bool) {
	s.mu.Lock()
	set := s.set
	if !set.Enabled || s.busy {
		s.mu.Unlock()
		return
	}
	if !force && s.now().Hour() < set.RunHour {
		s.mu.Unlock()
		return
	}
	s.busy = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.busy, s.activity = false, ""
		s.mu.Unlock()
	}()
	days, err := s.pending(ctx)
	if err != nil || len(days) == 0 {
		return
	}
	now := s.now().UTC()
	s.mu.Lock()
	s.st.LastRun = &now
	s.mu.Unlock()
	for _, d := range days {
		if ctx.Err() != nil {
			return
		}
		rec, err := s.archiveDay(ctx, set, d.Day)
		s.mu.Lock()
		if err != nil {
			s.st.LastError = fmt.Sprintf("%s: archiving %s: %v", s.now().UTC().Format(time.RFC3339), d.Day.Format("2006-01-02"), err)
			s.mu.Unlock()
			s.d.Log.Warn("backup: archive failed", "day", d.Day.Format("2006-01-02"), "err", err)
			s.saveState(ctx)
			return
		}
		t := s.now().UTC()
		s.st.Days[rec.Day] = rec
		s.st.LastSuccess, s.st.LastError = &t, ""
		s.mu.Unlock()
		s.saveState(ctx)
		s.d.Log.Info("backup: archived a day", "day", rec.Day, "events", rec.Events, "bytes", rec.Bytes, "key", rec.Key)
	}
}

// archiveDay streams one UTC day into the bucket and writes its manifest.
func (s *Service) archiveDay(ctx context.Context, set Settings, day time.Time) (DayRecord, error) {
	label := day.Format("2006-01-02")
	s.mu.Lock()
	s.activity = "archiving " + label
	s.mu.Unlock()
	c := set.client()
	key := set.dayKey(day)
	up, err := c.NewUpload(ctx, key, "application/zstd")
	if err != nil {
		return DayRecord{}, err
	}
	h := sha256.New()
	zw, err := zstd.NewWriter(io.MultiWriter(up, h), zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		up.Abort()
		return DayRecord{}, err
	}
	nl := []byte{'\n'}
	n, err := s.d.Export(ctx, day, day.AddDate(0, 0, 1), set.SkipModules, func(raw string) error {
		if _, err := io.WriteString(zw, raw); err != nil {
			return err
		}
		_, err := zw.Write(nl)
		return err
	})
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		up.Abort()
		return DayRecord{}, err
	}
	if err := up.Close(); err != nil {
		return DayRecord{}, err
	}
	rec := DayRecord{Day: label, Key: key, Events: n, Bytes: up.Size, SHA256: hex.EncodeToString(h.Sum(nil)), UploadedAt: s.now().UTC()}
	man, _ := json.MarshalIndent(map[string]any{
		"format": Format, "day": label, "events": n, "bytes": rec.Bytes, "sha256": rec.SHA256,
		"skip_modules": set.SkipModules, "created": rec.UploadedAt,
		"note": "Newline-delimited HomeXDR event JSON, zstd-compressed. Import it from Data retention in the HomeXDR console.",
	}, "", "  ")
	mc := *c
	mc.StorageClass = "" // the manifest stays readable even when archives use a cold class
	if err := mc.Put(ctx, key+".manifest.json", "application/json", man); err != nil {
		return rec, fmt.Errorf("write manifest: %w", err)
	}
	return rec, nil
}

// ArchivedDay is one day in the bucket, for the import list.
type ArchivedDay struct {
	Day     string `json:"day"`
	Key     string `json:"key"`
	Events  int64  `json:"events,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	InStore bool   `json:"in_store"` // the event store already has events for this day
}

var dayKeyRe = regexp.MustCompile(`homexdr-events-(\d{8})\.ndjson\.zst$`)

// Archived lists the archives in the bucket, newest first.
func (s *Service) Archived(ctx context.Context) ([]ArchivedDay, error) {
	s.mu.Lock()
	set := s.set
	recs := make(map[string]DayRecord, len(s.st.Days))
	for k, v := range s.st.Days {
		recs[k] = v
	}
	s.mu.Unlock()
	if set.Endpoint == "" || set.Bucket == "" {
		return []ArchivedDay{}, nil
	}
	keys, err := set.client().List(ctx, set.prefix(), 100000)
	if err != nil {
		return nil, err
	}
	local := map[string]bool{}
	if u, err := s.d.Usage(ctx); err == nil {
		for _, d := range u.Days {
			local[d.Day.Format("2006-01-02")] = true
		}
	}
	out := []ArchivedDay{}
	for _, k := range keys {
		m := dayKeyRe.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		t, err := time.Parse("20060102", m[1])
		if err != nil {
			continue
		}
		day := t.Format("2006-01-02")
		a := ArchivedDay{Day: day, Key: k, InStore: local[day]}
		if r, ok := recs[day]; ok {
			a.Events, a.Bytes = r.Events, r.Bytes
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day > out[j].Day })
	return out, nil
}

// Import brings an archived day back into the event store in the background. It refuses
// a day the store already has events for, so nothing is duplicated.
func (s *Service) Import(ctx context.Context, day string) error {
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return &InputError{"day must be YYYY-MM-DD"}
	}
	s.mu.Lock()
	set := s.set
	if s.busy {
		s.mu.Unlock()
		return &InputError{"a backup or import is already running"}
	}
	if set.Endpoint == "" || set.Bucket == "" || set.Secret == "" {
		s.mu.Unlock()
		return &InputError{"set up the bucket first"}
	}
	s.mu.Unlock()
	if u, err := s.d.Usage(ctx); err == nil {
		for _, d := range u.Days {
			if d.Day.Equal(t) {
				return &InputError{day + " is already in HomeXDR; it can only be imported after it has been removed"}
			}
		}
	}
	s.mu.Lock()
	if s.busy {
		s.mu.Unlock()
		return &InputError{"a backup or import is already running"}
	}
	s.busy, s.activity = true, "importing "+day
	s.mu.Unlock()
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		n, err := s.importDay(bg, set, t)
		s.mu.Lock()
		s.busy, s.activity = false, ""
		if err != nil {
			s.st.LastError = fmt.Sprintf("%s: importing %s: %v", s.now().UTC().Format(time.RFC3339), day, err)
		}
		s.mu.Unlock()
		s.saveState(bg)
		if err != nil {
			s.d.Log.Warn("backup: import failed", "day", day, "imported", n, "err", err)
		} else {
			s.d.Log.Info("backup: imported a day", "day", day, "events", n)
		}
	}()
	return nil
}

func (s *Service) importDay(ctx context.Context, set Settings, day time.Time) (int64, error) {
	r, err := set.client().Get(ctx, set.dayKey(day))
	if err != nil {
		var se *S3Error
		if errors.As(err, &se) && se.Code == "InvalidObjectState" {
			return 0, fmt.Errorf("the archive is in a cold storage class that must be restored in your provider's console before it can be read: %w", err)
		}
		return 0, err
	}
	defer r.Close()
	zr, err := zstd.NewReader(r)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var n int64
	batch := make([]*event.Event, 0, 2000)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := s.d.Insert(ctx, batch); err != nil {
			return err
		}
		n += int64(len(batch))
		batch = batch[:0]
		s.mu.Lock()
		s.activity = fmt.Sprintf("importing %s: %d events", day.Format("2006-01-02"), n)
		s.mu.Unlock()
		return nil
	}
	for sc.Scan() {
		var e event.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, fmt.Errorf("line %d: %w", n+int64(len(batch))+1, err)
		}
		batch = append(batch, &e)
		if len(batch) == cap(batch) {
			if err := flush(); err != nil {
				return n, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, flush()
}

// IsArchived reports whether a day is archived (for retention warnings).
func (s *Service) IsArchived(day time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.st.Days[day.Format("2006-01-02")]
	return ok
}

// Enabled reports whether backups are on.
func (s *Service) Enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set.Enabled
}

// View is the console's backup section.
type View struct {
	Settings
	SecretSet    bool        `json:"secret_set"`
	Activity     string      `json:"activity,omitempty"`
	LastRun      *time.Time  `json:"last_run,omitempty"`
	LastSuccess  *time.Time  `json:"last_success,omitempty"`
	LastError    string      `json:"last_error,omitempty"`
	ArchivedDays int         `json:"archived_days"`
	ArchivedSize int64       `json:"archived_bytes"`
	Pending      []string    `json:"pending"` // completed days not archived yet, oldest first
	Recent       []DayRecord `json:"recent"`
}

// View returns the settings (without the secret) and the state.
func (s *Service) View(ctx context.Context) View {
	pend, _ := s.pending(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	v := View{Settings: s.set, SecretSet: s.set.Secret != "", Activity: s.activity, LastRun: s.st.LastRun,
		LastSuccess: s.st.LastSuccess, LastError: s.st.LastError, Pending: []string{}, Recent: []DayRecord{}}
	v.Secret = ""
	if v.SkipModules == nil {
		v.SkipModules = []string{}
	}
	for _, d := range pend {
		v.Pending = append(v.Pending, d.Day.Format("2006-01-02"))
	}
	for _, r := range s.st.Days {
		v.ArchivedDays++
		v.ArchivedSize += r.Bytes
		v.Recent = append(v.Recent, r)
	}
	sort.Slice(v.Recent, func(i, j int) bool { return v.Recent[i].Day > v.Recent[j].Day })
	if len(v.Recent) > 30 {
		v.Recent = v.Recent[:30]
	}
	return v
}
