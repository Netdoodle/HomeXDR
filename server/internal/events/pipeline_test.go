package events

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

func TestSplunkFilterTerms(t *testing.T) {
	cases := map[string]Node{
		`index=opnsense`:   TermNode{Field: "event.module", Op: "eq", Value: "opnsense"},
		`dest_port>1024`:   TermNode{Field: "destination.port", Op: "gt", Value: "1024"},
		`src_port<=80`:     TermNode{Field: "source.port", Op: "lte", Value: "80"},
		`user!=root`:       NotNode{Child: TermNode{Field: "user.name", Op: "eq", Value: "root"}},
		`host=web*`:        TermNode{Field: "host.name", Op: "like", Value: "web*"},
		`action=*`:         TermNode{Field: "event.action", Op: "exists"},
		`msg="a b"`:        TermNode{Field: "msg", Op: "eq", Value: "a b"},
		`a=b=c`:            TermNode{Field: "a", Op: "eq", Value: "b=c"},
		`=foo`:             TermNode{Op: "like", Value: "=foo"},
		`foo=`:             TermNode{Op: "like", Value: "foo="},
		`x<y`:              TermNode{Op: "like", Value: "x<y"},
		`dest_port:>=1024`: TermNode{Field: "destination.port", Op: "gte", Value: "1024"},
		`a || b`:           OrNode{Children: []Node{TermNode{Op: "like", Value: "a"}, TermNode{Op: "like", Value: "b"}}},
	}
	for q, want := range cases {
		got, err := ParseQuery(q)
		if err != nil {
			t.Errorf("ParseQuery(%q): %v", q, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ParseQuery(%q) = %#v, want %#v", q, got, want)
		}
	}
}

func TestParsePipeline(t *testing.T) {
	good := map[string]int{ // query: number of commands
		`error`:           0,
		`a || b`:          0,
		`don't | head`:    1,
		`x | stats count`: 1,
		`| stats count, avg(size) as avg_bytes, dc(src) by host, action`: 1,
		`| timechart span=5m limit=3 count by action`:                    1,
		`| top limit=5 dest_port | sort -count | head 3`:                 3,
		`| rare src`:                     1,
		`| table _time, host 'odd name'`: 1,
		`| fields host`:                  1,
		`| sort 20 -count, +host`:        1,
		`| dedup 2 host, src`:            1,
		`| where dest_port > 1024 AND (action = "block" OR NOT isnull(src))`: 1,
		`| eval kb = round(size / 1024, 2), who = user . "@" . host`:         1,
		`| rename src as source, dest as "Destination IP"`:                   1,
		`| rex field=message "user (?<user>\w+) from (?<ip>[\d.]+)"`:         1,
		`| search action=block`:                                          1,
		`| where match(message, "a|b") | stats count`:                    2,
		`| eval x = case(a > 1, "big", a > 0, "small")`:                  1,
		`| stats count as "Event count" by host`:                         1,
		`| stats max(dest_port) by host | where 'max(dest_port)' > 1000`: 2,
	}
	for q, n := range good {
		p, err := ParsePipeline(q)
		if err != nil {
			t.Errorf("ParsePipeline(%q): %v", q, err)
			continue
		}
		if len(p.Commands) != n {
			t.Errorf("ParsePipeline(%q): %d commands, want %d", q, len(p.Commands), n)
		}
	}
	bad := []string{
		`| bogus`, `| stats`, `| stats count by`, `| stats avg`, `| stats count, count`,
		`| timechart count | head`, `| timechart span=5x count`, `| sort`, `| head -1`, `| limit`,
		`| table`, `| rex "no groups (\w+)"`, `| rex "(?<a>[)"`, `| eval x`, `| where (a`,
		`| where a = `, `| rename a b`, `| top`, `x |`, `| search (a`,
	}
	for _, q := range bad {
		if _, err := ParsePipeline(q); err == nil {
			t.Errorf("ParsePipeline(%q): want error", q)
		}
	}
}

func TestRewriteRegex(t *testing.T) {
	re, names, err := rewriteRegex(`(a|b) user=(?<user>\w+) ([0-9]+) (?P<n>\d+) [(]`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `(?:a|b) user=(\w+) (?:[0-9]+) (\d+) [(]`; re != want {
		t.Errorf("rewrite = %q, want %q", re, want)
	}
	if !reflect.DeepEqual(names, []string{"user", "n"}) {
		t.Errorf("names = %v", names)
	}
}

func TestSQLitePipelines(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	testPipelines(t, s, "p1", "p2")
}

// TestClickHousePipelines runs against a real server when HOMEXDR_TEST_CLICKHOUSE_DSN is set.
func TestClickHousePipelines(t *testing.T) {
	dsn := os.Getenv("HOMEXDR_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("HOMEXDR_TEST_CLICKHOUSE_DSN not set")
	}
	s, err := OpenClickHouse(context.Background(), dsn, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	suffix := event.NewID()
	testPipelines(t, s, "p1-"+suffix, "p2-"+suffix)
}

// pipeFixtures stores 5 OPNsense filterlog events and 3 process events.
func pipeFixtures(t *testing.T, s Store, h1, h2 string) time.Time {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	var evs []*event.Event
	fw := []struct {
		host, action, src string
		port              int
		size              int
		ago               time.Duration
	}{
		{h1, "block", "198.51.100.1", 22, 100, 50 * time.Minute},
		{h1, "block", "198.51.100.1", 22, 200, 40 * time.Minute},
		{h1, "block", "198.51.100.2", 443, 300, 30 * time.Minute},
		{h2, "pass", "10.0.0.5", 443, 4000, 20 * time.Minute},
		{h2, "pass", "10.0.0.6", 53, 50, 10 * time.Minute},
	}
	for _, f := range fw {
		evs = append(evs, &event.Event{
			ID: event.NewID(), Timestamp: now.Add(-f.ago),
			Host:        event.Host{ID: f.host, Name: f.host},
			Event:       event.Meta{Kind: event.KindEvent, Category: []string{"network"}, Type: []string{"connection"}, Module: "opnsense", Dataset: "opnsense.filterlog", Action: f.action},
			Source:      &event.Endpoint{IP: f.src, Port: 40000},
			Destination: &event.Endpoint{IP: "192.168.120.20", Port: f.port},
			Data:        map[string]any{"size": f.size, "rule": "rule " + f.action},
			Network:     &event.Network{Transport: "tcp", Bytes: int64(f.size) * 2},
			Message:     fmt.Sprintf("filterlog %s %s -> %d", f.action, f.src, f.port),
		})
	}
	for i, u := range []string{"alice", "bob", "alice"} {
		e := sample(h1, fmt.Sprintf("e-%d", i), "", "sshd", "sshd -D", []string{"process", "authentication"}, "start", now.Add(-time.Duration(5+i)*time.Minute))
		e.Message = "user " + u + " logged in from 10.0.0." + fmt.Sprint(i)
		evs = append(evs, e)
	}
	if err := s.Insert(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	return now
}

func testPipelines(t *testing.T, s Store, h1, h2 string) {
	ctx := context.Background()
	now := pipeFixtures(t, s, h1, h2)
	run := func(q string) *SearchResult {
		t.Helper()
		res, err := s.Search(ctx, SearchQuery{Query: q, From: now.Add(-2 * time.Hour), To: now.Add(time.Minute), HostIDs: []string{h1, h2}})
		if err != nil {
			t.Fatalf("Search(%q): %v", q, err)
		}
		return res
	}
	// table renders a table result as "a=1 b=2; ..." for comparison.
	table := func(q string) string {
		t.Helper()
		res := run(q)
		if res.Mode != "table" {
			t.Fatalf("Search(%q): mode %q, want table", q, res.Mode)
		}
		var rows []string
		for _, r := range res.Rows {
			var cells []string
			for i, c := range res.Columns {
				v := r[i]
				if f, ok := v.(float64); ok && f == float64(int64(f)) {
					v = int64(f)
				}
				cells = append(cells, fmt.Sprintf("%s=%v", c.Name, v))
			}
			rows = append(rows, strings.Join(cells, " "))
		}
		return strings.Join(rows, "; ")
	}
	expect := func(q, want string) {
		t.Helper()
		if got := table(q); got != want {
			t.Errorf("%s\n got: %s\nwant: %s", q, got, want)
		}
	}

	// Plain filters still return events; Splunk-style terms filter.
	if res := run(`index=opnsense action=block`); res.Mode != "events" || res.Total != 3 || len(res.Events) != 3 {
		t.Errorf("index=opnsense action=block: mode %s total %d", res.Mode, res.Total)
	}
	if res := run(`index=opnsense dest_port>100 action!=pass`); res.Total != 1 {
		t.Errorf("dest_port>100 action!=pass: total %d, want 1", res.Total)
	}

	expect(`index=opnsense | stats count`, `count=5`)
	expect(`index=opnsense | stats count by action`, `action=block count=3; action=pass count=2`)
	expect(`index=opnsense | stats count, dc(src) as sources, sum(size) as total, max(dest_port) by action | sort -total`,
		`action=pass count=2 sources=2 total=4050 max(dest_port)=443; action=block count=3 sources=2 total=600 max(dest_port)=443`)
	expect(`index=opnsense | stats avg(data.size) as avg by host | where avg > 1000`, `host=`+h2+` avg=2025`)
	expect(`index=opnsense size>=300 | stats count`, `count=2`)
	expect(`index=opnsense bytes>=600 | stats sum(bytes) as b, sum(network.bytes) as nb`, `b=8600 nb=8600`)
	expect(`index=opnsense | stats count by action | eval pct = count * 100 / 5 | table action, pct`,
		`action=block pct=60; action=pass pct=40`)
	expect(`index=opnsense | stats count by host | rename count as n, host as h | where n > 2`, `h=`+h1+` n=3`)
	expect(`index=opnsense | top limit=2 dest_port`, `dest_port=22 count=2 percent=40; dest_port=443 count=2 percent=40`)
	expect(`index=opnsense | rare limit=1 dest_port`, `dest_port=53 count=1 percent=20`)
	expect(`| stats count by category`, `category=authentication count=3; category=network count=5; category=process count=3`)
	expect(`index=opnsense | stats values(action) as actions`, `actions=[block pass]`)
	expect(`index=opnsense | eval kind = if(dest_port = 22, "ssh", "other") | stats count by kind`, `kind=other count=3; kind=ssh count=2`)
	expect(`index=opnsense | eval kb = size / 1024 | where kb > 0.25 | stats count`, `count=2`)
	expect(`index=opnsense | where like(src, "198.51.%") AND dest_port != 443 | stats count`, `count=2`)
	expect(`index=opnsense | search action=pass | stats count`, `count=2`)
	expect(`index=opnsense | where action="BLOCK" | stats count`, `count=3`)
	expect(`index=opnsense | where category="network" | stats count`, `count=5`)
	expect(`index=opnsense | eval x = coalesce(nosuch, action) . "/" . tostring(dest_port) | stats count by x | head 1`, `x=block/22 count=2`)
	expect(`index=opnsense | eval s = substr(src, 1, 3), n = len(src), u = upper(action) | dedup s | table s, n, u`,
		`s=10. n=8 u=PASS; s=198 n=12 u=BLOCK`)
	expect(`index=opnsense | sort dest_port, -size | head 2 | table dest_port, size`, `dest_port=22 size=200; dest_port=22 size=100`)
	expect(`index=opnsense | sort -size | head 3 | sort size | table size`, `size=200; size=300; size=4000`)
	expect(`index=opnsense | head 2 | stats count`, `count=2`)
	expect(`index=opnsense | dedup 2 action | stats count by action`, `action=block count=2; action=pass count=2`)
	expect(`| rex field=message "user (?<u>\w+) logged in from (?<ip>[\d.]+)" | where u != "" | stats count by u`, `u=alice count=2; u=bob count=1`)
	expect(`| where match(message, "^user (alice|carol)") | stats count`, `count=2`)
	expect(`| eval inj = "'; DROP TABLE events; --" | stats count by inj`, `inj='; DROP TABLE events; -- count=8`)
	expect(`index=opnsense | stats count(src) as c, count(nosuch) as none`, `c=5 none=0`)
	expect(`index=opnsense | eval big = size >= 300 | where big | stats count`, `count=2`)
	expect(`index=opnsense | eval r = round(size / 3, 1), a = abs(0 - size), z = 7 % 4 | sort a | head 1 | table r, a, z`, `r=16.7 a=50 z=3`)
	expect(`index=opnsense | eval n = null() | where isnull(n) AND isnotnull(action) | stats count`, `count=5`)
	expect(`index=opnsense | eval t = case(size > 1000, "big", size > 150, "mid") | stats count by t`, `t=big count=1; t=mid count=2`)

	// Times come back as RFC 3339.
	res := run(`index=opnsense | stats min(_time) as first, max(_time) as last`)
	if len(res.Rows) != 1 || res.Columns[0].Type != "time" {
		t.Fatalf("min/max(_time): %+v", res)
	}
	if first, _ := time.Parse(time.RFC3339Nano, res.Rows[0][0].(string)); !first.Equal(now.Add(-50 * time.Minute)) {
		t.Errorf("min(_time) = %v, want %v", res.Rows[0][0], now.Add(-50*time.Minute))
	}

	// Events-mode pipelines: head, dedup and eval fields.
	res = run(`index=opnsense | eval kb = size / 1000 | sort -kb | head 2`)
	if res.Mode != "events" || res.Total != 2 || len(res.Events) != 2 || len(res.Extra) != 2 {
		t.Fatalf("events pipeline: mode %s total %d events %d extra %d", res.Mode, res.Total, len(res.Events), len(res.Extra))
	}
	if res.Extra[0]["kb"] != 4.0 || res.Events[0].Data["size"] != 4000.0 {
		t.Errorf("events pipeline: first extra %v, data %v", res.Extra[0], res.Events[0].Data)
	}
	if res = run(`index=opnsense | dedup action`); res.Total != 2 || res.Events[0].Event.Action != "pass" {
		t.Errorf("dedup action: total %d", res.Total)
	}

	// timechart: one column per series, zero-filled buckets.
	res = run(`index=opnsense | timechart span=10m count by action`)
	if res.Chart != "timechart" || res.TimelineSpan != 600 {
		t.Fatalf("timechart: chart %q span %d", res.Chart, res.TimelineSpan)
	}
	if names := colNames(res); names != "_time,block,pass" {
		t.Errorf("timechart columns: %s", names)
	}
	var block, pass int64
	for _, r := range res.Rows {
		block += r[1].(int64)
		pass += r[2].(int64)
	}
	if block != 3 || pass != 2 || len(res.Rows) < 12 {
		t.Errorf("timechart: block %d pass %d rows %d", block, pass, len(res.Rows))
	}
	res = run(`index=opnsense | timechart span=1h limit=1 sum(size) by host`)
	if names := colNames(res); names != "_time,"+h2+",OTHER" {
		t.Errorf("timechart limit: columns %s", names)
	}
	res = run(`index=opnsense | timechart avg(size)`)
	if names := colNames(res); names != "_time,avg(size)" || res.TimelineSpan == 0 {
		t.Errorf("timechart no by: columns %s span %d", names, res.TimelineSpan)
	}

	// Timeline counts the filter's events.
	tl, err := s.Search(ctx, SearchQuery{Query: `index=opnsense | stats count`, From: now.Add(-time.Hour), To: now, HostIDs: []string{h1, h2}, Timeline: true})
	if err != nil {
		t.Fatal(err)
	}
	var sum int64
	for _, b := range tl.Timeline {
		sum += b.Count
	}
	if sum != 5 || tl.TimelineSpan != 60 || len(tl.Timeline) < 60 || len(tl.Timeline) > 61 {
		t.Errorf("timeline: sum %d span %d buckets %d", sum, tl.TimelineSpan, len(tl.Timeline))
	}

	// Errors are query errors.
	for _, q := range []string{
		`| stats count by host | search x`, `| stats count | table host`, `| where action`,
		`| eval x = nosuch(1)`, `| stats count | timechart count`, `| eval x = round(1, y)`,
		`| table 'a;b'`, `| timechart span=1s count`,
	} {
		_, err := s.Search(ctx, SearchQuery{Query: q, From: now.Add(-7 * 24 * time.Hour), HostIDs: []string{h1, h2}})
		if !IsQueryError(err) {
			t.Errorf("Search(%q): want a query error, got %v", q, err)
		}
	}
}

func colNames(res *SearchResult) string {
	var names []string
	for _, c := range res.Columns {
		names = append(names, c.Name)
	}
	return strings.Join(names, ",")
}
