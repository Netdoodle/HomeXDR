package adguard

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DatasetPiHole is event.dataset of Pi-hole lookups.
const DatasetPiHole = "dns.pihole"

// piHole reads Pi-hole v6's query log over its REST API (/api). It logs in once with the
// password (an app password works, and skips two-factor) and keeps the session, because
// Pi-hole allows only a few sessions at a time.
type piHole struct {
	c *Client

	mu  sync.Mutex
	sid string
	ok  bool // logged in
}

func newPiHole(set Settings) (*piHole, error) {
	c, err := newHTTP(set)
	if err != nil {
		return nil, err
	}
	c.product = productPiHole
	return &piHole{c: c}, nil
}

func (p *piHole) login(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"password": p.c.pass})
	var r struct {
		Session struct {
			Valid   bool    `json:"valid"`
			SID     *string `json:"sid"`
			Message string  `json:"message"`
		} `json:"session"`
	}
	if err := p.c.do(ctx, http.MethodPost, "/api/auth", nil, body, nil, &r); err != nil {
		return err
	}
	if !r.Session.Valid {
		return authError(productPiHole)
	}
	p.sid, p.ok = "", true
	if r.Session.SID != nil {
		p.sid = *r.Session.SID // nil when Pi-hole has no password set
	}
	return nil
}

// call sends an authenticated GET, logging in first, and once more if the session expired.
func (p *piHole) call(ctx context.Context, path string, q url.Values, v any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for try := 0; ; try++ {
		if !p.ok {
			if err := p.login(ctx); err != nil {
				return err
			}
		}
		sid := p.sid
		err := p.c.do(ctx, http.MethodGet, path, q, nil, func(r *http.Request) {
			if sid != "" {
				r.Header.Set("X-FTL-SID", sid)
			}
		}, v)
		if err != nil && errors.Is(err, errAuthBase) && try == 0 {
			p.ok = false // the session expired: log in again
			continue
		}
		return err
	}
}

func (p *piHole) Status(ctx context.Context) (*Status, error) {
	var r struct {
		Version struct {
			Core struct {
				Local struct {
					Version string `json:"version"`
				} `json:"local"`
			} `json:"core"`
			FTL struct {
				Local struct {
					Version string `json:"version"`
				} `json:"local"`
			} `json:"ftl"`
		} `json:"version"`
	}
	if err := p.call(ctx, "/api/info/version", nil, &r); err != nil {
		return nil, err
	}
	v := r.Version.Core.Local.Version
	if v == "" {
		v = r.Version.FTL.Local.Version
	}
	return &Status{Version: v, Running: true}, nil
}

// piQuery is one entry of GET /api/queries.
type piQuery struct {
	ID     int64   `json:"id"`
	Time   float64 `json:"time"`
	Type   string  `json:"type"`
	Domain string  `json:"domain"`
	Status string  `json:"status"`
	Client struct {
		IP   string  `json:"ip"`
		Name *string `json:"name"`
	} `json:"client"`
	Reply struct {
		Type string  `json:"type"`
		Time float64 `json:"time"`
	} `json:"reply"`
	Upstream *string `json:"upstream"`
}

// QueryLog pages through /api/queries. The token carries Pi-hole's cursor (the newest
// query when paging began, so new queries don't shift the pages) and the offset.
func (p *piHole) QueryLog(ctx context.Context, token string, limit int) (*Page, error) {
	q, _ := url.ParseQuery(token)
	q.Set("length", strconv.Itoa(limit))
	start, _ := strconv.Atoi(q.Get("start"))
	var r struct {
		Queries []piQuery `json:"queries"`
		Cursor  *int64    `json:"cursor"`
	}
	if err := p.call(ctx, "/api/queries", q, &r); err != nil {
		return nil, err
	}
	pg := &Page{Data: make([]Entry, 0, len(r.Queries))}
	for i := range r.Queries {
		pg.Data = append(pg.Data, r.Queries[i].entry())
	}
	if len(r.Queries) == limit {
		next := url.Values{"start": {strconv.Itoa(start + len(r.Queries))}}
		if r.Cursor != nil {
			next.Set("cursor", strconv.FormatInt(*r.Cursor, 10))
		}
		for _, k := range []string{"until", "disk"} {
			if v := q.Get(k); v != "" {
				next.Set(k, v)
			}
		}
		pg.Oldest = next.Encode()
	}
	return pg, nil
}

// StartBefore reads from Pi-hole's long-term database, which keeps more than the
// in-memory log, up to t.
func (p *piHole) StartBefore(t time.Time) string {
	return url.Values{"until": {strconv.FormatInt(t.Unix(), 10)}, "disk": {"true"}}.Encode()
}

// Close logs out, freeing the session.
func (p *piHole) Close(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ok || p.sid == "" {
		return
	}
	sid := p.sid
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = p.c.do(ctx, http.MethodDelete, "/api/auth", nil, nil, func(r *http.Request) { r.Header.Set("X-FTL-SID", sid) }, nil)
	p.ok, p.sid = false, ""
}

// piBlocked are the statuses of lookups Pi-hole blocked rather than answered.
var piBlocked = map[string]bool{
	"GRAVITY": true, "REGEX": true, "DENYLIST": true, "BLACKLIST": true,
	"GRAVITY_CNAME": true, "REGEX_CNAME": true, "DENYLIST_CNAME": true, "BLACKLIST_CNAME": true,
	"EXTERNAL_BLOCKED_IP": true, "EXTERNAL_BLOCKED_NULL": true, "EXTERNAL_BLOCKED_NXRA": true,
	"EXTERNAL_BLOCKED_EDE15": true, "SPECIAL_DOMAIN": true,
}

func (q *piQuery) entry() Entry {
	sec, frac := math.Modf(q.Time)
	at := time.Unix(int64(sec), int64(frac*1e9)).UTC()
	e := Entry{
		Time: at.Format(time.RFC3339Nano), Client: q.Client.IP, Status: piRcode(q.Reply.Type),
		Reason: q.Status, Cached: strings.HasPrefix(q.Status, "CACHE"),
		kind: KindPiHole, block: piBlocked[q.Status],
	}
	e.Question.Name, e.Question.Type, e.Question.Class = q.Domain, q.Type, "IN"
	if q.Client.Name != nil && *q.Client.Name != "" {
		e.ClientInfo = &struct {
			Name string `json:"name"`
		}{Name: *q.Client.Name}
	}
	if q.Upstream != nil {
		e.Upstream = *q.Upstream
	}
	if q.Reply.Time >= 0 && q.Reply.Type != "" && q.Reply.Type != "UNKNOWN" {
		e.Elapsed, _ = json.Marshal(q.Reply.Time)
	}
	return e
}

// piRcode turns Pi-hole's reply type into a DNS response code.
func piRcode(t string) string {
	switch strings.ToUpper(t) {
	case "IP", "CNAME", "DOMAIN", "RRNAME", "NODATA", "DNSSEC", "BLOB":
		return "NOERROR"
	case "NXDOMAIN", "SERVFAIL", "REFUSED", "NOTIMP":
		return strings.ToUpper(t)
	case "", "NONE", "UNKNOWN":
		return ""
	}
	return strings.ToUpper(t)
}
