package adguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DatasetTechnitium is event.dataset of Technitium DNS Server lookups.
const DatasetTechnitium = "dns.technitium"

// technitium reads Technitium DNS Server's query log. Technitium keeps it through a query
// log app (such as "Query Logs (Sqlite)" from its App Store), which HomeXDR finds by
// itself. The API token travels in the request body, never in the address.
type technitium struct {
	c *Client

	mu        sync.Mutex
	app, path string // the query log app's name and class path
}

func newTechnitium(set Settings) (*technitium, error) {
	c, err := newHTTP(set)
	if err != nil {
		return nil, err
	}
	c.product = productTechnitium
	return &technitium{c: c}, nil
}

// tnReply is the envelope of every Technitium API answer.
type tnReply struct {
	Status       string          `json:"status"`
	ErrorMessage string          `json:"errorMessage"`
	Response     json.RawMessage `json:"response"`
	Info         *struct {
		Version string `json:"version"`
	} `json:"info"`
}

func (t *technitium) call(ctx context.Context, path string, form url.Values, v any) (*tnReply, error) {
	if form == nil {
		form = url.Values{}
	}
	form.Set("token", t.c.pass)
	var r tnReply
	if err := t.c.do(ctx, http.MethodPost, path, nil, form, nil, &r); err != nil {
		return nil, err
	}
	switch r.Status {
	case "ok":
	case "invalid-token":
		return nil, authError(productTechnitium)
	default:
		msg := r.ErrorMessage
		if msg == "" {
			msg = "status " + r.Status
		}
		return nil, fmt.Errorf("Technitium DNS Server refused %s: %s", path, msg)
	}
	if v != nil && len(r.Response) > 0 {
		if err := json.Unmarshal(r.Response, v); err != nil {
			return nil, fmt.Errorf("Technitium DNS Server's answer was not what HomeXDR expected: %w", err)
		}
	}
	return &r, nil
}

// findLogger looks for an installed app that keeps the query log.
func (t *technitium) findLogger(ctx context.Context) error {
	var r struct {
		Apps []struct {
			Name    string `json:"name"`
			DNSApps []struct {
				ClassPath     string `json:"classPath"`
				IsQueryLogger bool   `json:"isQueryLogger"`
			} `json:"dnsApps"`
		} `json:"apps"`
	}
	if _, err := t.call(ctx, "/api/apps/list", nil, &r); err != nil {
		return err
	}
	for _, a := range r.Apps {
		for _, d := range a.DNSApps {
			if d.IsQueryLogger {
				t.app, t.path = a.Name, d.ClassPath
				return nil
			}
		}
	}
	return errors.New(`Technitium DNS Server has no query log app. Install "Query Logs (Sqlite)" from its App Store (Apps → App Store)`)
}

func (t *technitium) Status(ctx context.Context) (*Status, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.findLogger(ctx); err != nil {
		return nil, err
	}
	st := &Status{Running: true}
	// The version is a nicety: an API token may not be allowed to read the session.
	if r, err := t.call(ctx, "/api/user/session/get", nil, nil); err == nil && r.Info != nil {
		st.Version = r.Info.Version
	}
	return st, nil
}

// tnEntry is one entry of /api/logs/query.
type tnEntry struct {
	Timestamp    string   `json:"timestamp"`
	Client       string   `json:"clientIpAddress"`
	Protocol     string   `json:"protocol"`
	ResponseType string   `json:"responseType"`
	ResponseRtt  *float64 `json:"responseRtt"`
	Rcode        string   `json:"rcode"`
	Qname        string   `json:"qname"`
	Qtype        string   `json:"qtype"`
	Qclass       string   `json:"qclass"`
	Answer       string   `json:"answer"`
}

// QueryLog pages through the query log app, newest first. New lookups arriving while
// paging shift entries onto later pages; the poller skips the repeats.
func (t *technitium) QueryLog(ctx context.Context, token string, limit int) (*Page, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.app == "" {
		if err := t.findLogger(ctx); err != nil {
			return nil, err
		}
	}
	page := 1
	if q, _ := url.ParseQuery(token); q.Get("page") != "" {
		page, _ = strconv.Atoi(q.Get("page"))
	}
	form := url.Values{
		"name": {t.app}, "classPath": {t.path}, "pageNumber": {strconv.Itoa(page)},
		"entriesPerPage": {strconv.Itoa(limit)}, "descendingOrder": {"true"},
	}
	var r struct {
		PageNumber int       `json:"pageNumber"`
		TotalPages int       `json:"totalPages"`
		Entries    []tnEntry `json:"entries"`
	}
	if _, err := t.call(ctx, "/api/logs/query", form, &r); err != nil {
		return nil, err
	}
	pg := &Page{Data: make([]Entry, 0, len(r.Entries))}
	for i := range r.Entries {
		if e, ok := r.Entries[i].entry(); ok {
			pg.Data = append(pg.Data, e)
		}
	}
	if len(r.Entries) == limit && page < r.TotalPages {
		pg.Oldest = url.Values{"page": {strconv.Itoa(page + 1)}}.Encode()
	}
	return pg, nil
}

// StartBefore cannot seek: the history import reads from the newest and skips ahead.
func (t *technitium) StartBefore(time.Time) string { return "" }

// Close does nothing: the API token is not a session.
func (t *technitium) Close(context.Context) {}

func (te *tnEntry) entry() (Entry, bool) {
	at, err := time.Parse(time.RFC3339Nano, te.Timestamp)
	if err != nil {
		return Entry{}, false
	}
	rt := te.ResponseType
	e := Entry{
		Time: at.UTC().Format(time.RFC3339Nano), Client: te.Client, Status: tnRcode(te.Rcode),
		Reason: rt, Cached: strings.Contains(rt, "Cached"), ClientProto: strings.ToLower(te.Protocol),
		kind: KindTechnitium, block: strings.Contains(rt, "Blocked"),
	}
	e.Question.Name, e.Question.Type, e.Question.Class = te.Qname, te.Qtype, te.Qclass
	if te.ResponseRtt != nil {
		e.Elapsed, _ = json.Marshal(*te.ResponseRtt)
	}
	for _, a := range strings.Split(te.Answer, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		typ := ""
		if ip, err := netip.ParseAddr(a); err == nil {
			typ = "A"
			if ip.Unmap().Is6() {
				typ = "AAAA"
			}
		}
		v, _ := json.Marshal(a)
		e.Answer = append(e.Answer, struct {
			Type  string          `json:"type"`
			Value json.RawMessage `json:"value"`
			TTL   int             `json:"ttl"`
		}{Type: typ, Value: v})
	}
	return e, true
}

// tnRcode turns Technitium's response code names into the usual ones.
func tnRcode(s string) string {
	switch strings.ToLower(s) {
	case "noerror":
		return "NOERROR"
	case "nxdomain":
		return "NXDOMAIN"
	case "servfail", "serverfailure":
		return "SERVFAIL"
	case "refused":
		return "REFUSED"
	case "notimp", "notimplemented":
		return "NOTIMP"
	case "formerr", "formaterror":
		return "FORMERR"
	}
	return strings.ToUpper(s)
}
