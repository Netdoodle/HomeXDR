package core

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
)

// Inbound threats: who on the internet is trying to reach the firewall, from where, and at
// which ports. Built from the firewall log at query time, so it covers stored history too.
// Countries and networks come from the offline IP network list (Settings → Offline lists),
// never from an outside service.

// inboundBase selects firewall log rows of connections arriving at the firewall.
//
// A port forward logs two lines for one packet: the "rdr" translation (to the WAN address)
// and then the filter rule's pass or block (to the inside address). The rdr line is not a
// verdict, as a forwarded packet can still be blocked, so it is left out and the filter
// line that follows counts the attempt once.
//
// DHCP replies to the firewall's own lease (server port 67 to client port 68, and 547 to
// 546 for DHCPv6) are the ISP handing out the WAN address, not someone trying to get in.
const inboundBase = `event.dataset:opnsense.filterlog network.direction:inbound NOT event.action:rdr` +
	` NOT (network.transport:udp source.port:67 destination.port:68)` +
	` NOT (network.transport:udp source.port:547 destination.port:546)`

// notPrivateSource leaves out sources inside the home network (RFC 1918, link-local,
// loopback, Tailscale's CGNAT range, IPv6 unique-local and link-local). The query language
// has no address ranges, so they are spelled as prefixes.
var notPrivateSource = func() string {
	p := []string{"10.*", "192.168.*", "127.*", "169.254.*", "fe80:*", "fc*", "fd*", "::1"}
	for i := 16; i <= 31; i++ {
		p = append(p, fmt.Sprintf("172.%d.*", i))
	}
	for i := 64; i <= 127; i++ {
		p = append(p, fmt.Sprintf("100.%d.*", i))
	}
	terms := make([]string, len(p))
	for i, s := range p {
		terms[i] = "source.ip:" + s
	}
	return "NOT (" + strings.Join(terms, " OR ") + ")"
}()

// InboundCountry is one country's share of the attempts.
type InboundCountry struct {
	Code     string `json:"code"` // ISO 3166-1 alpha-2, "" when unknown
	Attempts int64  `json:"attempts"`
	Sources  int    `json:"sources"`
	Allowed  int64  `json:"allowed"`
	// Last is the newest attempt from the country.
	Last time.Time `json:"last"`
}

// InboundSource is one address that tried to connect.
type InboundSource struct {
	IP       string    `json:"ip"`
	Country  string    `json:"country,omitempty"`
	ASN      int       `json:"asn,omitempty"`
	ASName   string    `json:"as_name,omitempty"`
	Attempts int64     `json:"attempts"`
	Allowed  int64     `json:"allowed"`
	Ports    int64     `json:"ports"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
}

// InboundNetwork is one autonomous system (hosting provider, ISP, scanning service).
type InboundNetwork struct {
	ASN      int    `json:"asn"`
	Name     string `json:"name"`
	Country  string `json:"country,omitempty"`
	Attempts int64  `json:"attempts"`
	Sources  int    `json:"sources"`
}

// InboundPort is one targeted port.
type InboundPort struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Attempts  int64  `json:"attempts"`
	Sources   int64  `json:"sources"`
}

// InboundPoint is one time bucket.
type InboundPoint struct {
	T       time.Time `json:"t"`
	Blocked int64     `json:"blocked"`
	Allowed int64     `json:"allowed"`
	Sources int64     `json:"sources"` // distinct internet sources in the bucket
}

// InboundView is the inbound threats page.
type InboundView struct {
	Hours      int              `json:"hours"`
	SpanSec    int64            `json:"span_sec"`
	Attempts   int64            `json:"attempts"`
	Blocked    int64            `json:"blocked"`
	Allowed    int64            `json:"allowed"`
	Sources    int              `json:"sources"`
	Countries  []InboundCountry `json:"countries"`
	TopSources []InboundSource  `json:"top_sources"`
	AllowedIn  []InboundSource  `json:"allowed_sources"`
	Networks   []InboundNetwork `json:"networks"`
	Ports      []InboundPort    `json:"ports"`
	Timeline   []InboundPoint   `json:"timeline"`
	// The same window just before this one, for trends.
	PrevAttempts int64 `json:"prev_attempts"`
	PrevBlocked  int64 `json:"prev_blocked"`
	PrevSources  int64 `json:"prev_sources"`
	// NoGeo is set when the offline IP network list is not loaded, so no country is known.
	NoGeo bool `json:"no_geo,omitempty"`
	// HomeCountry is the country of the firewall's own public address, where the map's
	// arcs end.
	HomeCountry string `json:"home_country,omitempty"`
	// Truncated is set when there were more sources than one query returns; the rarest are left out.
	Truncated bool `json:"truncated,omitempty"`
}

const inboundMaxSources = 50000

func inboundSpan(hours int) (string, int64) {
	switch {
	case hours <= 1:
		return "5m", 300
	case hours <= 6:
		return "15m", 900
	case hours <= 48:
		return "1h", 3600
	case hours <= 24*7:
		return "6h", 6 * 3600
	}
	return "1d", 86400
}

func publicAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return a, false
	}
	a = a.Unmap()
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	if !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) {
		return a, false
	}
	return a, true
}

func allowedAction(a string) bool { return a == "pass" || a == "nat" }

// InboundThreats builds the inbound threats view for the last hours.
func (c *Core) InboundThreats(ctx context.Context, hours int) (*InboundView, error) {
	now := time.Now().UTC()
	from := now.Add(-time.Duration(hours) * time.Hour)
	span, spanSec := inboundSpan(hours)
	v := &InboundView{Hours: hours, SpanSec: spanSec, Countries: []InboundCountry{}, TopSources: []InboundSource{},
		AllowedIn: []InboundSource{}, Networks: []InboundNetwork{}, Ports: []InboundPort{}, Timeline: []InboundPoint{}}

	// 1. Every source address: count, ports tried, first and last seen, by action.
	bySrc, truncated, err := c.inboundSources(ctx, from)
	if err != nil {
		return nil, err
	}
	v.Truncated = truncated

	geo := false
	countries := map[string]*InboundCountry{}
	networks := map[int]*InboundNetwork{}
	all := make([]*InboundSource, 0, len(bySrc))
	for _, s := range bySrc {
		if s.Country != "" || s.ASN != 0 {
			geo = true
		}
		all = append(all, s)
		v.Attempts += s.Attempts
		v.Allowed += s.Allowed
		cc := countries[s.Country]
		if cc == nil {
			cc = &InboundCountry{Code: s.Country}
			countries[s.Country] = cc
		}
		cc.Attempts += s.Attempts
		cc.Allowed += s.Allowed
		cc.Sources++
		if s.Last.After(cc.Last) {
			cc.Last = s.Last
		}
		if s.ASN != 0 {
			nw := networks[s.ASN]
			if nw == nil {
				nw = &InboundNetwork{ASN: s.ASN, Name: s.ASName, Country: s.Country}
				networks[s.ASN] = nw
			}
			nw.Attempts += s.Attempts
			nw.Sources++
		}
	}
	v.Blocked = v.Attempts - v.Allowed
	v.Sources = len(all)
	v.NoGeo = len(all) > 0 && !geo
	if c.Enrich != nil {
		for a := range c.firewallOwn() {
			if _, ok := publicAddr(a); ok {
				if cc := c.Enrich.IP(a).Country; cc != "" {
					v.HomeCountry = cc
					break
				}
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Attempts > all[j].Attempts })
	for _, s := range all {
		if len(v.TopSources) < 50 {
			v.TopSources = append(v.TopSources, *s)
		}
		if s.Allowed > 0 && len(v.AllowedIn) < 50 {
			v.AllowedIn = append(v.AllowedIn, *s)
		}
	}
	for _, cc := range countries {
		v.Countries = append(v.Countries, *cc)
	}
	sort.Slice(v.Countries, func(i, j int) bool { return v.Countries[i].Attempts > v.Countries[j].Attempts })
	for _, nw := range networks {
		v.Networks = append(v.Networks, *nw)
	}
	sort.Slice(v.Networks, func(i, j int) bool { return v.Networks[i].Attempts > v.Networks[j].Attempts })
	if len(v.Networks) > 25 {
		v.Networks = v.Networks[:25]
	}

	// 2. Targeted ports, from internet sources only.
	public := inboundBase + " " + notPrivateSource
	if res, err := c.Events.Search(ctx, events.SearchQuery{From: from, Query: public +
		` | stats count, dc(source.ip) as sources by destination.port, network.transport | sort -count | head 25`}); err == nil {
		for _, row := range res.Rows {
			if len(row) < 4 {
				continue
			}
			v.Ports = append(v.Ports, InboundPort{Port: int(toInt64(row[0])), Transport: fmt.Sprint(row[1]),
				Attempts: toInt64(row[2]), Sources: toInt64(row[3])})
		}
	}

	// 3. Attempts over time.
	if res, err := c.Events.Search(ctx, events.SearchQuery{From: from, Query: public +
		` | timechart span=` + span + ` count by event.action`}); err == nil && len(res.Columns) > 0 {
		for _, row := range res.Rows {
			if len(row) == 0 {
				continue
			}
			t, ok := toTime(row[0])
			if !ok {
				continue
			}
			p := InboundPoint{T: t}
			for i := 1; i < len(row) && i < len(res.Columns); i++ {
				n := toInt64(row[i])
				if allowedAction(res.Columns[i].Name) {
					p.Allowed += n
				} else {
					p.Blocked += n
				}
			}
			v.Timeline = append(v.Timeline, p)
		}
	}
	if len(v.Timeline) > 0 {
		if res, err := c.Events.Search(ctx, events.SearchQuery{From: from, Query: public +
			` | timechart span=` + span + ` dc(source.ip)`}); err == nil {
			at := map[int64]int64{}
			for _, row := range res.Rows {
				if len(row) >= 2 {
					if t, ok := toTime(row[0]); ok {
						at[t.Unix()] = toInt64(row[1])
					}
				}
			}
			for i := range v.Timeline {
				v.Timeline[i].Sources = at[v.Timeline[i].T.Unix()]
			}
		}
	}

	// 4. The window before, for the trend arrows.
	prevFrom := from.Add(-time.Duration(hours) * time.Hour)
	if res, err := c.Events.Search(ctx, events.SearchQuery{From: prevFrom, To: from, Query: public +
		` | stats count, dc(source.ip) as sources by event.action`}); err == nil {
		for _, row := range res.Rows {
			if len(row) < 3 {
				continue
			}
			n := toInt64(row[1])
			v.PrevAttempts += n
			if !allowedAction(fmt.Sprint(row[0])) {
				v.PrevBlocked += n
			}
			v.PrevSources += toInt64(row[2]) // per action; sources rarely both pass and block
		}
	}
	return v, nil
}

// inboundSources aggregates the internet sources seen since from, with their country and
// network. truncated is set when there were more sources than one query returns.
func (c *Core) inboundSources(ctx context.Context, from time.Time) (map[string]*InboundSource, bool, error) {
	res, err := c.Events.Search(ctx, events.SearchQuery{From: from, Query: inboundBase +
		` | stats count, dc(destination.port) as ports, min(@timestamp) as first, max(@timestamp) as last by source.ip, event.action` +
		fmt.Sprintf(` | sort -count | head %d`, inboundMaxSources)})
	if err != nil {
		return nil, false, err
	}
	bySrc := map[string]*InboundSource{}
	for _, row := range res.Rows {
		if len(row) < 6 {
			continue
		}
		ip := fmt.Sprint(row[0])
		if _, ok := publicAddr(ip); !ok {
			continue
		}
		s := bySrc[ip]
		if s == nil {
			s = &InboundSource{IP: ip}
			bySrc[ip] = s
		}
		n := toInt64(row[2])
		s.Attempts += n
		if allowedAction(fmt.Sprint(row[1])) {
			s.Allowed += n
		}
		if p := toInt64(row[3]); p > s.Ports {
			s.Ports = p // distinct ports per action; the larger is a fair floor
		}
		if t, ok := toTime(row[4]); ok && (s.First.IsZero() || t.Before(s.First)) {
			s.First = t
		}
		if t, ok := toTime(row[5]); ok && t.After(s.Last) {
			s.Last = t
		}
	}
	if c.Enrich != nil {
		for _, s := range bySrc {
			info := c.Enrich.IP(s.IP)
			s.Country, s.ASN, s.ASName = info.Country, info.ASN, info.ASName
		}
	}
	return bySrc, res.Truncated || len(res.Rows) >= inboundMaxSources, nil
}

// InboundEventsView is a page of the firewall events behind one number on the threat map.
type InboundEventsView struct {
	Events []any `json:"events"`
	Total  int64 `json:"total"`
	// Sources is how many internet addresses the selection covers.
	Sources int `json:"sources"`
	// Query reproduces the selection on the Search page; empty when it would name too many
	// addresses to fit in a link.
	Query string `json:"query,omitempty"`
}

const (
	inboundEventsPage   = 100
	inboundQueryMaxIPs  = 60
	inboundEventsMaxIPs = 5000
)

// allowedActionsQuery and its negation select connections let in or blocked.
const allowedActionsQuery = `(event.action:pass OR event.action:nat)`

// InboundEvents returns the firewall events from one country's internet sources (all,
// blocked or let in) in the last hours, newest first. The country is looked up per source
// address, the way the map counts it, and turned into a list of addresses for the search.
func (c *Core) InboundEvents(ctx context.Context, hours int, country, kind, category string, offset int) (*InboundEventsView, error) {
	from := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	if kind == "ids" {
		q, n, err := c.idsEventsQuery(ctx, from, country, category)
		if err != nil {
			return nil, err
		}
		v := &InboundEventsView{Events: []any{}, Sources: n}
		if q == "" {
			return v, nil
		}
		res, err := c.Events.Search(ctx, events.SearchQuery{From: from, Query: q, Limit: inboundEventsPage, Offset: offset})
		if err != nil {
			return nil, err
		}
		v.Total = res.Total
		for _, e := range res.Events {
			v.Events = append(v.Events, e)
		}
		if n <= inboundQueryMaxIPs/2 {
			v.Query = q
		}
		return v, nil
	}
	bySrc, _, err := c.inboundSources(ctx, from)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, s := range bySrc {
		if s.Country != country {
			continue
		}
		switch kind {
		case "allowed":
			if s.Allowed == 0 {
				continue
			}
		case "blocked":
			if s.Attempts-s.Allowed == 0 {
				continue
			}
		}
		ips = append(ips, s.IP)
	}
	v := &InboundEventsView{Events: []any{}, Sources: len(ips)}
	if len(ips) == 0 {
		return v, nil
	}
	if len(ips) > inboundEventsMaxIPs {
		// The busiest sources: enough to show events, and keeps the query bounded.
		sort.Slice(ips, func(i, j int) bool { return bySrc[ips[i]].Attempts > bySrc[ips[j]].Attempts })
		ips = ips[:inboundEventsMaxIPs]
	}
	sort.Strings(ips)
	terms := make([]string, len(ips))
	for i, ip := range ips {
		terms[i] = "source.ip:" + quoteValue(ip)
	}
	q := inboundBase
	switch kind {
	case "allowed":
		q += " " + allowedActionsQuery
	case "blocked":
		q += " NOT " + allowedActionsQuery
	}
	q += " (" + strings.Join(terms, " OR ") + ")"
	res, err := c.Events.Search(ctx, events.SearchQuery{From: from, Query: q, Limit: inboundEventsPage, Offset: offset})
	if err != nil {
		return nil, err
	}
	v.Total = res.Total
	for _, e := range res.Events {
		v.Events = append(v.Events, e)
	}
	if len(ips) <= inboundQueryMaxIPs {
		v.Query = q
	}
	return v, nil
}

// quoteValue quotes a search value when it holds characters the query language reads
// specially (IPv6 colons).
func quoteValue(s string) string {
	if strings.ContainsAny(s, ` :()"*?`) {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
