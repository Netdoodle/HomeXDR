package core

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
)

// IDS threats on the threat map: Suricata alerts by threat, category and country. The remote
// side of each alert (the attacker for inbound traffic, the far end for outbound) is placed
// on the map, using the offline IP network list like the rest of the page.

const idsBase = `event.module:suricata event.kind:alert`

// groupSuffix joins reputation signatures split into numbered groups ("… group 212").
var groupSuffix = regexp.MustCompile(`\s+group\s+\d+$`)

func threatName(sig string) string { return groupSuffix.ReplaceAllString(strings.TrimSpace(sig), "") }

// IDSThreat is one threat (a signature, groups joined) over the window.
type IDSThreat struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Severity   string `json:"severity"` // high, medium, low
	Count      int64  `json:"count"`
	Sources    int    `json:"sources"`
	Countries  int    `json:"countries"`
	TopCountry string `json:"top_country,omitempty"`
	// Spark counts the threat per time bucket (IDSView.Buckets).
	Spark []int64 `json:"spark"`
}

// IDSCountry is one country's IDS alerts by category.
type IDSCountry struct {
	Code       string           `json:"code"`
	Total      int64            `json:"total"`
	Sources    int              `json:"sources"`
	ByCategory map[string]int64 `json:"by_category"`
	// MaxSeverity is the worst alert from the country: high, medium or low.
	MaxSeverity string `json:"max_severity"`
	maxSev      int64
}

// IDSView is the IDS part of the threat map.
type IDSView struct {
	Hours      int          `json:"hours"`
	SpanSec    int64        `json:"span_sec"`
	Buckets    []time.Time  `json:"buckets"`
	Total      int64        `json:"total"`
	Threats    []IDSThreat  `json:"threats"`
	Categories []string     `json:"categories"` // most frequent first
	Countries  []IDSCountry `json:"countries"`
	Truncated  bool         `json:"truncated,omitempty"`
}

func idsSeverity(n int64) string {
	switch {
	case n >= 73:
		return "high"
	case n >= 47:
		return "medium"
	}
	return "low"
}

// remoteAddr picks the far side of an alert: the source when it is on the internet and not
// the firewall itself, otherwise the destination when that is.
func remoteAddr(src, dst string, own map[string]bool) string {
	if _, ok := publicAddr(src); ok && !own[src] {
		return src
	}
	if _, ok := publicAddr(dst); ok && !own[dst] {
		return dst
	}
	return ""
}

func (c *Core) firewallOwn() map[string]bool {
	own := map[string]bool{}
	if c.Inventory != nil {
		for _, a := range c.Inventory.FirewallAddrs() {
			own[a] = true
		}
		for _, a := range c.Inventory.Settings().FirewallIPs {
			if p, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
				own[p.String()] = true
			}
		}
	}
	return own
}

const idsMaxRows = 100000

// InboundIDS summarizes Suricata alerts of the last hours by threat, category and country.
func (c *Core) InboundIDS(ctx context.Context, hours int) (*IDSView, error) {
	from := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	span, spanSec := inboundSpan(hours)
	v := &IDSView{Hours: hours, SpanSec: spanSec, Buckets: []time.Time{}, Threats: []IDSThreat{}, Categories: []string{}, Countries: []IDSCountry{}}

	res, err := c.Events.Search(ctx, events.SearchQuery{From: from, Query: idsBase +
		` | stats count, max(event.severity) as sev by rule.name, rule.category, source.ip, destination.ip` +
		fmt.Sprintf(` | sort -count | head %d`, idsMaxRows)})
	if err != nil {
		return nil, err
	}
	v.Truncated = res.Truncated || len(res.Rows) >= idsMaxRows
	own := c.firewallOwn()
	geo := map[string]string{} // remote address → country
	country := func(ip string) string {
		if cc, ok := geo[ip]; ok {
			return cc
		}
		cc := ""
		if c.Enrich != nil {
			cc = c.Enrich.IP(ip).Country
		}
		geo[ip] = cc
		return cc
	}
	type threatAcc struct {
		IDSThreat
		sev       int64
		sources   map[string]bool
		byCountry map[string]int64
	}
	threats := map[string]*threatAcc{}
	countries := map[string]*IDSCountry{}
	countrySources := map[string]map[string]bool{}
	cats := map[string]int64{}
	for _, row := range res.Rows {
		if len(row) < 6 {
			continue
		}
		name := threatName(fmt.Sprint(row[0]))
		cat := fmt.Sprint(row[1])
		if cat == "" || cat == "<nil>" {
			cat = "Uncategorized"
		}
		remote := remoteAddr(fmt.Sprint(row[2]), fmt.Sprint(row[3]), own)
		n := toInt64(row[4])
		sev := toInt64(row[5])
		v.Total += n
		cats[cat] += n
		t := threats[name]
		if t == nil {
			t = &threatAcc{IDSThreat: IDSThreat{Name: name, Category: cat}, sources: map[string]bool{}, byCountry: map[string]int64{}}
			threats[name] = t
		}
		t.Count += n
		if sev > t.sev {
			t.sev = sev
		}
		if remote == "" {
			continue
		}
		cc := country(remote)
		t.sources[remote] = true
		t.byCountry[cc] += n
		ct := countries[cc]
		if ct == nil {
			ct = &IDSCountry{Code: cc, ByCategory: map[string]int64{}}
			countries[cc] = ct
			countrySources[cc] = map[string]bool{}
		}
		ct.Total += n
		ct.ByCategory[cat] += n
		if sev > ct.maxSev {
			ct.maxSev = sev
		}
		countrySources[cc][remote] = true
	}
	for _, t := range threats {
		t.Severity = idsSeverity(t.sev)
		t.Sources = len(t.sources)
		t.Countries = len(t.byCountry)
		var best int64
		for cc, n := range t.byCountry {
			if cc != "" && n > best {
				best, t.TopCountry = n, cc
			}
		}
		v.Threats = append(v.Threats, t.IDSThreat)
	}
	sort.Slice(v.Threats, func(i, j int) bool { return v.Threats[i].Count > v.Threats[j].Count })
	if len(v.Threats) > 100 {
		v.Threats = v.Threats[:100]
	}
	for cc, ct := range countries {
		ct.Sources = len(countrySources[cc])
		ct.MaxSeverity = idsSeverity(ct.maxSev)
		v.Countries = append(v.Countries, *ct)
	}
	sort.Slice(v.Countries, func(i, j int) bool { return v.Countries[i].Total > v.Countries[j].Total })
	for cat := range cats {
		v.Categories = append(v.Categories, cat)
	}
	sort.Slice(v.Categories, func(i, j int) bool { return cats[v.Categories[i]] > cats[v.Categories[j]] })

	// Sparklines: alerts per bucket by signature, joined into threats.
	if len(v.Threats) > 0 {
		ts, err := c.Events.Search(ctx, events.SearchQuery{From: from, Query: idsBase + ` | timechart span=` + span + ` limit=500 count by rule.name`})
		if err == nil && len(ts.Columns) > 1 {
			index := map[string]int{}
			for i, t := range v.Threats {
				index[t.Name] = i
				v.Threats[i].Spark = make([]int64, len(ts.Rows))
			}
			for b, row := range ts.Rows {
				if len(row) == 0 {
					continue
				}
				if t, ok := toTime(row[0]); ok {
					v.Buckets = append(v.Buckets, t)
				}
				for k := 1; k < len(row) && k < len(ts.Columns); k++ {
					if i, ok := index[threatName(ts.Columns[k].Name)]; ok {
						v.Threats[i].Spark[b] += toInt64(row[k])
					}
				}
			}
		}
	}
	return v, nil
}

// idsEventsQuery selects one country's IDS alerts, optionally of one category. The
// country's remote addresses come from the same aggregation as the map.
func (c *Core) idsEventsQuery(ctx context.Context, from time.Time, country, category string) (string, int, error) {
	res, err := c.Events.Search(ctx, events.SearchQuery{From: from, Query: idsBase +
		` | stats count by rule.category, source.ip, destination.ip` + fmt.Sprintf(` | sort -count | head %d`, idsMaxRows)})
	if err != nil {
		return "", 0, err
	}
	own := c.firewallOwn()
	seen := map[string]bool{}
	var ips []string
	for _, row := range res.Rows {
		if len(row) < 4 {
			continue
		}
		cat := fmt.Sprint(row[0])
		if cat == "" || cat == "<nil>" {
			cat = "Uncategorized"
		}
		if category != "" && cat != category {
			continue
		}
		remote := remoteAddr(fmt.Sprint(row[1]), fmt.Sprint(row[2]), own)
		if remote == "" || seen[remote] {
			continue
		}
		cc := ""
		if c.Enrich != nil {
			cc = c.Enrich.IP(remote).Country
		}
		if cc != country {
			continue
		}
		seen[remote] = true
		ips = append(ips, remote)
	}
	if len(ips) == 0 {
		return "", 0, nil
	}
	if len(ips) > inboundEventsMaxIPs {
		ips = ips[:inboundEventsMaxIPs]
	}
	sort.Strings(ips)
	terms := make([]string, 0, 2*len(ips))
	for _, ip := range ips {
		q := quoteValue(ip)
		terms = append(terms, "source.ip:"+q, "destination.ip:"+q)
	}
	q := idsBase
	if category != "" && category != "Uncategorized" {
		q += ` rule.category:"` + strings.ReplaceAll(category, `"`, `\"`) + `"`
	}
	return q + " (" + strings.Join(terms, " OR ") + ")", len(ips), nil
}
