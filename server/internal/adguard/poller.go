package adguard

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

const (
	settingsKey = "adguard_settings"
	stateKey    = "adguard_state"

	defaultInterval = 30
	pageSize        = 500
	// maxPages bounds one poll. Beyond it HomeXDR has fallen behind and skips ahead rather
	// than reading the whole log.
	maxPages   = 40
	ingestSize = 500
)

// Settings is the stored configuration. Password is write-only: it is never returned.
type Settings struct {
	// Kind is the resolver: adguard (also when empty), pihole or technitium.
	Kind     string `json:"kind,omitempty"`
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	// ServerName is the name to check the certificate against when the address is an IP.
	ServerName string `json:"server_name,omitempty"`
	// PinSHA256 trusts exactly the certificate with this fingerprint, instead of checking it.
	PinSHA256   string `json:"pin_sha256,omitempty"`
	IntervalSec int    `json:"interval_sec"`
}

// Input is a settings update from the console. An empty Password keeps the stored one
// unless ClearPassword is set.
type Input struct {
	Settings
	ClearPassword bool `json:"clear_password,omitempty"`
}

// View is the settings as the console sees them, with the poller's status.
type View struct {
	// Backfill is the history import's progress (filled in by the console handler).
	Backfill    BackfillStatus `json:"backfill"`
	Kind        string         `json:"kind"`
	Enabled     bool           `json:"enabled"`
	URL         string         `json:"url"`
	Username    string         `json:"username"`
	PasswordSet bool           `json:"password_set"`
	ServerName  string         `json:"server_name,omitempty"`
	PinSHA256   string         `json:"pin_sha256,omitempty"`
	IntervalSec int            `json:"interval_sec"`
	Status      Stats          `json:"status"`
}

// Stats is how polling is going.
type Stats struct {
	State       string     `json:"state"` // off, waiting, ok, error
	LastPoll    *time.Time `json:"last_poll,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	Version     string     `json:"version,omitempty"`
	Imported    int64      `json:"imported"`   // lookups stored since the server started
	LastBatch   int        `json:"last_batch"` // lookups stored by the last poll
	// FellBehind counts polls that found more new lookups than one poll reads; the
	// older part of each such burst was skipped.
	FellBehind int64      `json:"fell_behind"`
	Since      *time.Time `json:"since,omitempty"`
}

// state is where reading resumes, kept across restarts.
type state struct {
	Cursor string   `json:"cursor"`
	Seen   []string `json:"seen"`
	// Since is when importing started; older history is not imported.
	Since time.Time `json:"since"`
	// Backfilled is set once the history from before Since has been imported.
	Backfilled bool `json:"backfilled,omitempty"`
}

// Ingest stores a batch of events as coming from AdGuard Home's host.
type Ingest func(ctx context.Context, evs []*event.Event) error

// Poller reads new query log entries on a timer.
type Poller struct {
	st     *store.Store
	log    *slog.Logger
	ingest Ingest

	mu    sync.Mutex
	set   Settings
	stats Stats
	wake  chan struct{}
	// history stores backfilled lookups without detection (SetHistory).
	history  Ingest
	backfill BackfillStatus

	// src is the reader the last poll used, kept while the settings stay the same so a
	// resolver with login sessions (Pi-hole) is not logged into on every poll.
	src    source
	srcSet Settings
}

// New returns a poller. Call Load before Run.
func New(st *store.Store, log *slog.Logger, ingest Ingest) *Poller {
	return &Poller{st: st, log: log, ingest: ingest, wake: make(chan struct{}, 1)}
}

// Load reads the stored settings.
func (p *Poller) Load(ctx context.Context) error {
	set := Settings{IntervalSec: defaultInterval}
	if err := p.st.GetKV(ctx, settingsKey, &set); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	p.mu.Lock()
	p.set = set
	p.mu.Unlock()
	return nil
}

func (p *Poller) settings() Settings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.set
}

// View returns the settings without the password, and the status.
func (p *Poller) View() View {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.stats
	if !p.set.Enabled {
		st.State = "off"
	} else if st.State == "" {
		st.State = "waiting"
	}
	return View{
		Kind: normalKind(p.set.Kind), Enabled: p.set.Enabled, URL: p.set.URL, Username: p.set.Username, PasswordSet: p.set.Password != "",
		ServerName: p.set.ServerName, PinSHA256: p.set.PinSHA256, IntervalSec: p.set.IntervalSec, Status: st,
	}
}

// merge applies an input to the stored settings and validates the result.
func (p *Poller) merge(in Input) (Settings, error) {
	cur := p.settings()
	set := in.Settings
	set.Kind = normalKind(strings.TrimSpace(set.Kind))
	product := Product(set.Kind)
	set.URL = strings.TrimSpace(set.URL)
	set.Username = strings.TrimSpace(set.Username)
	set.ServerName = strings.TrimSpace(set.ServerName)
	set.PinSHA256 = strings.TrimSpace(set.PinSHA256)
	switch {
	case in.ClearPassword:
		set.Password = ""
	case set.Password == "" && normalKind(cur.Kind) == set.Kind:
		set.Password = cur.Password // a password is never carried over to another resolver
	}
	if !needsUsername(set.Kind) {
		set.Username = ""
	}
	if set.IntervalSec == 0 {
		set.IntervalSec = defaultInterval
	}
	if set.IntervalSec < 10 || set.IntervalSec > 3600 {
		return set, &InputError{"check every 10 to 3600 seconds"}
	}
	if set.URL == "" && !set.Enabled {
		return set, nil
	}
	u, err := ParseURL(set.URL)
	if err != nil {
		return set, &InputError{strings.Replace(err.Error(), "the resolver", product, 1)}
	}
	set.URL = u.String()
	if set.PinSHA256 != "" && !validPin(set.PinSHA256) {
		return set, &InputError{"the certificate fingerprint must be 64 hexadecimal characters (SHA-256)"}
	}
	if set.PinSHA256 != "" {
		set.PinSHA256 = colons(normalizePin(set.PinSHA256))
	}
	if (set.PinSHA256 != "" || set.ServerName != "") && u.Scheme != "https" {
		return set, &InputError{"a certificate name or fingerprint only applies to an https address"}
	}
	switch {
	case !set.Enabled:
	case set.Kind == KindAdGuard && (set.Username == "" || set.Password == ""):
		return set, &InputError{"enter AdGuard Home's username and password"}
	case set.Kind == KindPiHole && set.Password == "":
		return set, &InputError{"enter Pi-hole's password or an app password"}
	case set.Kind == KindTechnitium && set.Password == "":
		return set, &InputError{"enter a Technitium DNS Server API token"}
	}
	return set, nil
}

// InputError is a settings mistake to show the owner.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

// Save stores new settings. Changing the address starts reading afresh from now.
func (p *Poller) Save(ctx context.Context, in Input) (View, error) {
	set, err := p.merge(in)
	if err != nil {
		return View{}, err
	}
	cur := p.settings()
	if err := p.st.SetKV(ctx, settingsKey, set); err != nil {
		return View{}, err
	}
	if set.URL != cur.URL || set.Kind != normalKind(cur.Kind) {
		if err := p.st.SetKV(ctx, stateKey, state{}); err != nil {
			return View{}, err
		}
	}
	p.mu.Lock()
	p.set = set
	p.stats = Stats{}
	p.mu.Unlock()
	p.poke()
	return p.View(), nil
}

// TestResult is the outcome of a connection test.
type TestResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Version string `json:"version,omitempty"`
	// Certificate is set when the certificate check failed, so the owner can choose to trust it.
	Certificate *CertInfo `json:"certificate,omitempty"`
}

// Test tries the given settings (the stored password when none is given) without saving.
func (p *Poller) Test(ctx context.Context, in Input) (TestResult, error) {
	if strings.TrimSpace(in.URL) == "" {
		in.Settings = p.settings() // nothing given: test what is saved
	}
	in.Enabled = true
	set, err := p.merge(in)
	if err != nil {
		return TestResult{}, err
	}
	c, err := newSource(set)
	if err != nil {
		return TestResult{}, &InputError{err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	defer c.Close(context.WithoutCancel(ctx))
	product := Product(set.Kind)
	st, err := c.Status(ctx)
	if err != nil {
		res := TestResult{Message: err.Error()}
		var ce *CertError
		if errors.As(err, &ce) {
			if info, ferr := FetchCertificate(ctx, set); ferr == nil {
				res.Certificate = info
			}
		}
		return res, nil
	}
	page, err := c.QueryLog(ctx, "", 1)
	if err != nil {
		return TestResult{Message: "Connected, but reading the query log failed: " + err.Error(), Version: st.Version}, nil
	}
	msg := strings.TrimSpace("Connected to "+product+" "+st.Version) + "."
	if len(page.Data) == 0 {
		msg += " Its query log is empty or turned off, so there is nothing to read yet."
	} else {
		msg += " The query log is readable."
	}
	if strings.HasPrefix(set.URL, "http://") {
		msg += " The address is plain http, so the password crosses the network unencrypted."
	}
	return TestResult{OK: true, Message: msg, Version: st.Version}, nil
}

func (p *Poller) poke() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Run polls until ctx ends.
func (p *Poller) Run(ctx context.Context) {
	for {
		set := p.settings()
		wait := time.Duration(set.IntervalSec) * time.Second
		if set.Enabled {
			p.pollOnce(ctx, set)
		} else {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
		case <-time.After(wait):
		}
	}
}

func (p *Poller) pollOnce(ctx context.Context, set Settings) {
	now := time.Now().UTC()
	n, behind, version, since, err := p.poll(ctx, set)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.set != set {
		return // settings changed meanwhile; the next poll reports
	}
	p.stats.LastPoll = &now
	if behind {
		p.stats.FellBehind++
	}
	if !since.IsZero() {
		p.stats.Since = &since
	}
	if err != nil {
		if p.stats.State != "error" || p.stats.LastError != err.Error() {
			p.log.Warn("dns query log: poll failed", "resolver", Product(set.Kind), "err", err)
		}
		p.stats.State, p.stats.LastError = "error", err.Error()
		return
	}
	p.stats.State, p.stats.LastError = "ok", ""
	p.stats.LastSuccess = &now
	p.stats.LastBatch = n
	p.stats.Imported += int64(n)
	if version != "" {
		p.stats.Version = version
	}
}

// poll reads everything newer than the cursor and stores it. It returns the number of
// lookups stored and whether it fell behind.
func (p *Poller) poll(ctx context.Context, set Settings) (n int, behind bool, version string, since time.Time, err error) {
	c, err := p.source(ctx, set)
	if err != nil {
		return 0, false, "", since, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if p.View().Status.Version == "" {
		if st, err := c.Status(ctx); err == nil {
			version = st.Version
		}
	}
	var stt state
	if err := p.st.GetKV(ctx, stateKey, &stt); err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, false, version, since, err
	}
	cursor, _ := time.Parse(time.RFC3339Nano, stt.Cursor)
	seen := make(map[string]bool, len(stt.Seen))
	for _, k := range stt.Seen {
		seen[k] = true
	}

	var fresh []Entry
	got := map[string]bool{} // entries already taken this poll: pages can shift and repeat
	olderThan, reached := "", false
	for page := 0; page < maxPages && !reached; page++ {
		pg, err := c.QueryLog(ctx, olderThan, pageSize)
		if err != nil {
			return 0, false, version, stt.Since, err
		}
		for i := range pg.Data {
			e := &pg.Data[i]
			t, ok := e.When()
			if !ok {
				continue
			}
			if cursor.IsZero() {
				// First poll: start from now. Remember the newest instant and stop.
				stt = state{Cursor: e.Time, Since: time.Now().UTC()}
				for j := i; j < len(pg.Data) && pg.Data[j].Time == e.Time; j++ {
					stt.Seen = append(stt.Seen, pg.Data[j].key())
				}
				return 0, false, version, stt.Since, p.st.SetKV(ctx, stateKey, stt)
			}
			if t.Before(cursor) || (t.Equal(cursor) && seen[e.key()]) {
				reached = true
				break
			}
			if !got[e.key()] {
				got[e.key()] = true
				fresh = append(fresh, *e)
			}
		}
		if len(pg.Data) < pageSize || pg.Oldest == "" {
			reached = true
		}
		olderThan = pg.Oldest
	}
	if cursor.IsZero() {
		// The log is empty: start from now.
		stt = state{Cursor: time.Now().UTC().Format(time.RFC3339Nano), Since: time.Now().UTC()}
		return 0, false, version, stt.Since, p.st.SetKV(ctx, stateKey, stt)
	}
	if !reached {
		// Fell behind by more than maxPages: what lies between is skipped, not read late.
		p.log.Warn("dns query log: more new lookups than one poll reads; older ones skipped", "resolver", Product(set.Kind), "read", len(fresh))
	}
	if len(fresh) == 0 {
		return 0, !reached, version, stt.Since, nil
	}

	// Oldest first, so a failure part-way leaves the cursor at what was stored.
	for i, j := 0, len(fresh)-1; i < j; i, j = i+1, j-1 {
		fresh[i], fresh[j] = fresh[j], fresh[i]
	}
	for start := 0; start < len(fresh); start += ingestSize {
		chunk := fresh[start:min(start+ingestSize, len(fresh))]
		evs := make([]*event.Event, 0, len(chunk))
		for i := range chunk {
			if ev := chunk[i].Event(); ev != nil {
				evs = append(evs, ev)
			}
		}
		if len(evs) > 0 {
			if err := p.ingest(ctx, evs); err != nil {
				return n, !reached, version, stt.Since, err
			}
			n += len(evs)
		}
		last := chunk[len(chunk)-1]
		if last.Time != stt.Cursor {
			stt.Cursor, stt.Seen = last.Time, nil
		}
		for i := range chunk {
			if chunk[i].Time == stt.Cursor {
				stt.Seen = append(stt.Seen, chunk[i].key())
			}
		}
		if err := p.st.SetKV(ctx, stateKey, stt); err != nil {
			return n, !reached, version, stt.Since, err
		}
	}
	return n, !reached, version, stt.Since, nil
}

// source returns the reader for set, reusing the previous one while the settings are the
// same. A changed setting closes the old reader (logging out of Pi-hole).
func (p *Poller) source(ctx context.Context, set Settings) (source, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.src != nil && p.srcSet == set {
		return p.src, nil
	}
	if p.src != nil {
		p.src.Close(ctx)
		p.src = nil
	}
	src, err := newSource(set)
	if err != nil {
		return nil, err
	}
	p.src, p.srcSet = src, set
	return src, nil
}
