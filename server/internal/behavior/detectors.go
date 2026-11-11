package behavior

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Searches share these filters. The address filters are coarse: they keep the firewall's
// own WAN rows, which are most of its log, out of the grouping. Detectors then check each
// address exactly against the home network scope.
const (
	trafficFilter   = `(event.module:netflow OR event.module:opnsense OR event.dataset:suricata.flow)`
	internalSources = `(source.ip:10.* OR source.ip:192.168.* OR source.ip:172.* OR source.ip:fd*)`
	internalDests   = `(destination.ip:10.* OR destination.ip:192.168.* OR destination.ip:172.* OR destination.ip:fd*)`
	notBlocked      = `NOT event.action:block NOT event.action:reject`
	// Traffic a device started: its own port is the higher one. A reply goes the other way,
	// from the service's port back to the client's.
	initiated = `| where src_port > dest_port OR network.transport = "icmp"`
)

var reportedDays = func(def float64) Threshold {
	return Threshold{Key: "reported_days", Label: "Days before reporting again", Help: "The same thing is reported once in this many days.", Default: def, Min: 1, Max: 365}
}

var learningDays = func(def float64) Threshold {
	return Threshold{Key: "learning_days", Label: "Learning days", Help: "For this long what is seen becomes normal and nothing is reported. It starts when the input first arrives, and again when NetFlow first arrives.", Default: def, Min: 1, Max: 90}
}

func catalog() []*Spec {
	return []*Spec{
		{
			ID: "beaconing", Rule: "net:beaconing", Title: "Beaconing",
			About: "A device contacting one internet address at very even intervals, the way malware checks in with its controller. Push services, time sync and similar are left out.",
			Need:  needTraffic, Every: time.Hour, run: runBeaconing,
			Thresholds: []Threshold{
				{"min_count", "Minimum check-ins", "Fewer connections than this are not looked at.", 10, 3, 200},
				{"min_span_sec", "Minimum span in seconds", "The check-ins must cover at least this long.", 600, 60, 86400},
				{"max_cv", "Maximum variation", "How even the gaps must be: their spread divided by their average. Lower is stricter.", 0.15, 0.01, 1},
				{"min_interval_sec", "Shortest gap in seconds", "Gaps shorter than this on average are a busy connection, not a check-in.", 5, 1, 3600},
				{"window_hours", "Hours looked at", "A check-in slower than this divided by the minimum check-ins is not seen. Longer windows cost more.", 12, 1, 48},
				{"max_shared_by", "Devices sharing it", "If this many devices contact the same address, it is a common service and is left out.", 3, 2, 100},
				{"popular_rank", "Popular domain rank", "Domains ranked within this on the offline popularity list count as popular. Popular and used by a second device is left out; popular and used by one device is low severity.", 100000, 0, 10000000},
				{"fanout_per_day", "Reports per device and port a day", "Limits a client that polls many servers the same way.", 3, 1, 100},
				reportedDays(7),
			},
			Lists: []ListDef{
				{Key: "benign_domains", Label: "Domains to leave out", Help: "One per line. A domain covers its subdomains.", Kind: "domain"},
				{Key: "ignore_ports", Label: "Ports to leave out", Help: "One per line, such as tcp/8883 or 8883.", Kind: "port"},
			},
		},
		{
			ID: "dns_tunnel", Rule: "net:dns-tunnel", Title: "DNS tunnelling",
			About: "A device looking up many long or random-looking names under one domain, which is how data is smuggled out through DNS. Popular domains and local names are left out.",
			Need:  needDNS, run: runDNSTunnel,
			Thresholds: []Threshold{
				{"window_hours", "Hours looked at", "How far back each run looks.", 1, 0.25, 24},
				{"label_len", "Long label length", "A label at least this long counts as long.", 30, 10, 63},
				{"min_long_names", "Long names to report", "This many different names with a long label under one domain is reported.", 20, 2, 100000},
				{"entropy_min", "Random-looking entropy", "A label of 12 or more characters with at least this entropy, in bits per character, looks random.", 3.5, 1, 6},
				{"min_unique_names", "Unique names to report", "This many different names under one domain is reported if most look random.", 100, 5, 100000},
				{"min_random_share", "Share that must look random", "With many unique names, at least this share must look random. 0.5 means half.", 0.5, 0, 1},
				{"popular_rank", "Popular domain rank", "Domains ranked within this on the offline popularity list are left out.", 100000, 0, 10000000},
				reportedDays(7),
			},
			Lists: []ListDef{{Key: "ignore_domains", Label: "Domains to leave out", Help: "One per line. A domain covers its subdomains.", Kind: "domain"}},
		},
		{
			ID: "dns_bypass", Rule: "net:dns-bypass", Title: "DNS bypass",
			About: "A device sending DNS (port 53) or DNS over TLS (port 853) to something other than your resolver, so its lookups dodge your filtering and logs. Pairs seen while learning count as normal.",
			Need:  needTraffic, run: runDNSBypass,
			Thresholds: []Threshold{
				{"window_hours", "Hours looked at", "How far back each run looks.", 1, 0.25, 24},
				learningDays(3),
				reportedDays(7),
			},
			Lists: []ListDef{{Key: "approved_resolvers", Label: "Approved resolvers", Help: "One address per line. The firewall is always approved.", Kind: "ip"}},
		},
		{
			ID: "upload_spike", Rule: "net:upload-spike", Title: "Upload spike",
			About: "A device sending far more to the internet in an hour than it normally does at that hour. Each device has its own normal, so a camera that uploads all day is fine.",
			Need:  needFlows, run: runUploadSpike,
			Thresholds: []Threshold{
				{"factor", "Times its normal", "An hour must be at least this many times the device's normal for that hour.", 10, 2, 1000},
				{"min_mb", "Minimum megabytes", "An hour below this is never reported.", 500, 1, 1000000},
				{"min_samples", "Hours of history needed", "Earlier samples of that hour of day needed before comparing.", 5, 2, 14},
				learningDays(7),
				reportedDays(1),
			},
		},
		{
			ID: "unusual_port", Rule: "net:unusual-port", Title: "Unusual port",
			About: "A device connecting to the internet on a port no device here has used, as reverse shells and tunnels often do. High UDP ports are left out, since games and calls use them all the time.",
			Need:  needTraffic, run: runUnusualPort,
			Thresholds: []Threshold{
				{"window_hours", "Hours looked at", "How far back each run looks.", 1, 0.25, 24},
				learningDays(7),
				reportedDays(7),
			},
			Lists: []ListDef{{Key: "allowed_ports", Label: "Ports to leave out", Help: "One per line, such as tcp/8443 or 8443.", Kind: "port"}},
		},
		{
			ID: "internal_scan", Rule: "net:internal-scan", Title: "Internal scan",
			About: "A device reaching many other devices or many ports on one device, as scanners and spreading malware do. Only traffic that crosses the firewall is seen. Discovery protocols are left out.",
			Need:  needFirewall, run: runInternalScan,
			Thresholds: []Threshold{
				{"window_minutes", "Minutes looked at", "How far back each run looks.", 30, 5, 240},
				{"min_hosts", "Hosts reached", "Reaching this many other addresses is reported.", 30, 5, 65536},
				{"min_ports", "Ports on one host", "Reaching this many ports on one address is reported.", 30, 5, 65536},
				reportedDays(1),
			},
			Lists: []ListDef{{Key: "allowed_scanners", Label: "Devices to leave out", Help: "One address per line, for a monitoring box or a network scanner you run.", Kind: "ip"}},
		},
		{
			ID: "rogue_dhcp", Rule: "net:rogue-dhcp", Title: "Rogue DHCP server",
			About: "A device answering DHCP that is not the firewall, which could hand out a hostile gateway or DNS server. Servers seen while learning count as normal.",
			Need:  needFirewall, run: runRogueDHCP,
			Thresholds: []Threshold{
				{"window_hours", "Hours looked at", "How far back each run looks.", 1, 0.25, 24},
				learningDays(3),
				reportedDays(7),
			},
			Lists: []ListDef{{Key: "approved_servers", Label: "Approved DHCP servers", Help: "One address per line. The firewall is always approved.", Kind: "ip"}},
		},
		{
			ID: "exposure", Rule: "net:exposure", Title: "Exposed service",
			About: "Traffic from the internet allowed in to an internal device and port: a port forward or a UPnP mapping. Ones seen while learning count as normal.",
			Need:  needFirewall, run: runExposure,
			Thresholds: []Threshold{
				{"window_hours", "Hours looked at", "How far back each run looks.", 1, 0.25, 24},
				learningDays(3),
				reportedDays(30),
			},
			Lists: []ListDef{{Key: "expected", Label: "Expected services", Help: "One per line, such as 192.168.20.20:443, tcp/443 or 443.", Kind: "endpoint"}},
		},
	}
}

// --- beaconing ----------------------------------------------------------------------------

const (
	beatBurst    = 10 * time.Second // a retry within one beat, not a new beat
	maxBeatTimes = 60
	maxBeatPairs = 2000
	// reportTimerGap is the shortest gap, in seconds, an exporter's active timeout gives.
	reportTimerGap = 300
)

// beats merges retries and returns the gaps between beats, in seconds.
func beats(times []time.Time) (n int, gaps []float64) {
	var last time.Time
	for _, t := range times {
		if !last.IsZero() {
			g := t.Sub(last)
			if g < beatBurst {
				continue
			}
			gaps = append(gaps, g.Seconds())
		}
		last = t
		n++
	}
	return n, gaps
}

func meanStd(v []float64) (mean, std float64) {
	if len(v) == 0 {
		return 0, 0
	}
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	for _, x := range v {
		std += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(std / float64(len(v)))
}

type beacon struct {
	series events.ConnSeries
	n      int
	mean   float64
	cv     float64
	span   float64
}

func runBeaconing(rc *runCtx) error {
	from, to := rc.window(rc.value("window_hours"))
	minCount := int(rc.value("min_count"))
	series, err := rc.r.d.Events.ConnTimes(rc.Context, events.ConnTimesQuery{
		From: from, To: to, Modules: []string{event.ModuleNetFlow, event.ModuleOPNsense},
		MinCount: minCount, MaxSeries: maxBeatPairs, MaxTimes: max(maxBeatTimes, minCount),
	})
	if err != nil {
		return err
	}
	// How many devices talk to each destination, regular or not.
	users := map[string]map[string]bool{}
	var found []beacon
	for _, s := range series {
		src, ok := rc.home(s.Source)
		dst, ok2 := rc.addr(s.Destination)
		if !ok || !ok2 || !rc.scope.Public(dst) {
			continue
		}
		key, _ := rc.label(src.String())
		if users[s.Destination] == nil {
			users[s.Destination] = map[string]bool{}
		}
		users[s.Destination][key] = true
		if s.Transport == "udp" && housekeepingUDP(s.Port) || s.Transport == "tcp" && pushTCP(s.Port) {
			continue
		}
		if portListed(rc.listOf("ignore_ports"), "", s.Transport, s.Port) {
			continue
		}
		n, gaps := beats(s.Times)
		if n < minCount || len(gaps) == 0 {
			continue
		}
		span := s.Times[len(s.Times)-1].Sub(s.Times[0]).Seconds()
		mean, std := meanStd(gaps)
		if span < rc.value("min_span_sec") || mean < rc.value("min_interval_sec") || std/mean > rc.value("max_cv") {
			continue
		}
		// One long connection, cut into parts by the exporter's timers, looks perfectly
		// regular. Its source port gives it away; a check-in opens a new connection.
		if s.SourcePorts*2 < s.Count && (s.Transport == "tcp" || mean >= reportTimerGap) {
			continue
		}
		found = append(found, beacon{series: s, n: n, mean: mean, cv: std / mean, span: span})
	}
	if len(found) == 0 {
		return nil
	}
	names, err := rc.destinationNames(found, from, to)
	if err != nil {
		return err
	}
	nameUsers := map[string]map[string]bool{}
	for ip, name := range names {
		base := rc.registered(name)
		if nameUsers[base] == nil {
			nameUsers[base] = map[string]bool{}
		}
		for k := range users[ip] {
			nameUsers[base][k] = true
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].series.Count > found[j].series.Count })
	for _, b := range found {
		s := b.series
		name := names[s.Destination]
		if benignClass(name, rc.listOf("benign_domains")) != "" {
			continue
		}
		sharedBy := len(users[s.Destination])
		dest, popular := s.Destination, false
		if name != "" {
			base := rc.registered(name)
			dest = base
			popular = rc.popular(base, rc.value("popular_rank"))
			if n := len(nameUsers[base]); n > sharedBy {
				sharedBy = n
			}
		}
		if float64(sharedBy) >= rc.value("max_shared_by") || (popular && sharedBy >= 2) {
			continue
		}
		key, label := rc.label(s.Source)
		portKey := fmt.Sprintf("%s|%s/%d", key, s.Transport, s.Port)
		if rc.reportedWithin(portKey+"|"+dest, rc.value("reported_days")) || rc.reportedTodayUnder(portKey+"|") >= int(rc.value("fanout_per_day")) {
			continue
		}
		sev := store.SevMedium
		if popular {
			sev = store.SevLow
		}
		where := s.Destination
		if name != "" {
			where = fmt.Sprintf("%q (%s)", name, s.Destination)
		}
		if as := rc.asName(s.Destination); as != "" {
			where += ", " + as
		}
		text := fmt.Sprintf("%s contacted %s on %s/%d about every %s: %d check-ins over %s, with gaps varying only %.0f%%. Malware checks in with its controller like this, and so do some normal apps. Used by %d device(s) here.",
			label, where, s.Transport, s.Port, humanSeconds(b.mean), b.n, humanSeconds(b.span), b.cv*100, sharedBy)
		if popular {
			text += " The domain is popular, so this may well be an ordinary service."
		}
		rc.raise(Finding{
			Title: "Possible beaconing from " + label, Description: text, Severity: sev, Entity: portKey + "|" + dest,
			Source: &event.Endpoint{IP: s.Source}, Destination: &event.Endpoint{IP: s.Destination, Port: s.Port, Domain: name},
			Data: map[string]any{"interval_sec": round(b.mean), "check_ins": b.n, "span_sec": round(b.span), "variation": roundTo(b.cv, 3), "shared_by": sharedBy, "connections": s.Count},
		})
	}
	return nil
}

// reportedTodayUnder counts reports in the last day under a key prefix.
func (rc *runCtx) reportedTodayUnder(prefix string) int {
	n := 0
	for k, v := range rc.state {
		if !strings.HasPrefix(k, "r|"+prefix) {
			continue
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil && rc.now.Sub(t) < 24*time.Hour {
			n++
		}
	}
	return n
}

// destinationNames finds names for addresses from TLS and HTTP events, which carry them.
func (rc *runCtx) destinationNames(found []beacon, from, to time.Time) (map[string]string, error) {
	seen := map[string]bool{}
	var terms []string
	for _, b := range found {
		if seen[b.series.Destination] || len(terms) >= 200 {
			continue
		}
		seen[b.series.Destination] = true
		terms = append(terms, fmt.Sprintf("destination.ip:%q", b.series.Destination))
	}
	rows, err := rc.table("destination.domain:* ("+strings.Join(terms, " OR ")+") | stats count as n by destination.ip, destination.domain", from, to)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	best := map[string]float64{}
	for _, r := range rows {
		ip, n := r.str("destination.ip"), r.num("n")
		if n > best[ip] {
			best[ip], out[ip] = n, strings.ToLower(strings.TrimSuffix(r.str("destination.domain"), "."))
		}
	}
	return out, nil
}

// --- DNS tunnelling -----------------------------------------------------------------------

type dnsZone struct {
	names, long, random int
	queries             float64
	sample              string
	ip                  string
}

func runDNSTunnel(rc *runCtx) error {
	from, to := rc.window(rc.value("window_hours"))
	rows, err := rc.table("dns.question.name:* | stats count as n by source.ip, host.name, event.module, dns.question.name", from, to)
	if err != nil {
		return err
	}
	labelLen := int(rc.value("label_len"))
	minEntropy := rc.value("entropy_min")
	rank := rc.value("popular_rank")
	ignored := rc.listOf("ignore_domains")
	zones := map[[2]string]*dnsZone{}
	for _, r := range rows {
		name := strings.ToLower(strings.TrimSuffix(r.str("dns.question.name"), "."))
		if name == "" || localOnly(name) || suffixMatch(name, ignored) {
			continue
		}
		// A resolver's log names the client. An agent's lookups come from the machine itself,
		// often from a loopback or container address, so the machine is the device.
		ip := r.str("source.ip")
		who := ip
		if _, ok := rc.home(ip); !ok {
			if m := r.str("event.module"); m == event.ModuleDNS || m == event.ModuleSuricata {
				continue
			}
			ip, who = "", r.str("host.name")
		}
		base := rc.registered(name)
		if name == base || cdnDomains[base] || rc.popular(base, rank) {
			continue
		}
		k := [2]string{who, base}
		z := zones[k]
		if z == nil {
			z = &dnsZone{ip: ip}
			zones[k] = z
		}
		z.names++
		z.queries += r.num("n")
		longest := ""
		for _, l := range strings.Split(strings.TrimSuffix(name, "."+base), ".") {
			if len(l) > len(longest) {
				longest = l
			}
		}
		if len(longest) >= labelLen {
			z.long++
		}
		if len(longest) >= 12 && entropy(longest) >= minEntropy {
			z.random++
		}
		if len(name) > len(z.sample) {
			z.sample = name
		}
	}
	keys := make([][2]string, 0, len(zones))
	for k := range zones {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	for _, k := range keys {
		z := zones[k]
		manyLong := float64(z.long) >= rc.value("min_long_names")
		manyRandom := float64(z.names) >= rc.value("min_unique_names") && float64(z.random) >= rc.value("min_random_share")*float64(z.names)
		if !manyLong && !manyRandom {
			continue
		}
		deviceKey, label := k[0], k[0]
		if z.ip != "" {
			deviceKey, label = rc.label(z.ip)
		}
		text := fmt.Sprintf("%s looked up %d different names under %q in %s: %d with a label of %d or more characters, %d random-looking, %.0f lookups in all. Data can be smuggled out through DNS this way. Some security and anti-spam products also look up names like this. Longest name: %q.",
			label, z.names, k[1], humanSeconds(rc.value("window_hours")*3600), z.long, labelLen, z.random, z.queries, z.sample)
		f := Finding{
			Title: "Possible DNS tunnelling from " + label, Description: text, Severity: store.SevMedium, Entity: deviceKey + "|" + k[1],
			Destination: &event.Endpoint{Domain: k[1]},
			Data:        map[string]any{"domain": k[1], "unique_names": z.names, "long_names": z.long, "random_names": z.random, "lookups": z.queries, "sample": z.sample},
		}
		if z.ip != "" {
			f.Source = &event.Endpoint{IP: z.ip}
		}
		rc.raise(f)
	}
	return nil
}

// --- DNS bypass ---------------------------------------------------------------------------

func runDNSBypass(rc *runCtx) error {
	from, to := rc.window(rc.value("window_hours"))
	rows, err := rc.table(trafficFilter+" "+internalSources+" (destination.port:53 OR destination.port:853) | stats count as n by source.ip, destination.ip, destination.port, event.action", from, to)
	if err != nil {
		return err
	}
	approved := rc.listOf("approved_resolvers")
	type pair struct{ device, resolver string }
	type info struct {
		ip              string
		port            int
		allowed, denied float64
	}
	pairs := map[pair]*info{}
	for _, r := range rows {
		src, ok := rc.home(r.str("source.ip"))
		dstStr := r.str("destination.ip")
		dst, ok2 := rc.addr(dstStr)
		if !ok || !ok2 || rc.scope.IsFirewall(dst) || contains(approved, dst.String()) {
			continue
		}
		key, _ := rc.label(src.String())
		p := pair{key, dst.String()}
		in := pairs[p]
		if in == nil {
			in = &info{ip: src.String(), port: int(r.num("destination.port"))}
			pairs[p] = in
		}
		if a := r.str("event.action"); a == "block" || a == "reject" {
			in.denied += r.num("n")
		} else {
			in.allowed += r.num("n")
		}
	}
	learning := rc.learning()
	keys := make([]pair, 0, len(pairs))
	for p := range pairs {
		keys = append(keys, p)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].device+keys[i].resolver < keys[j].device+keys[j].resolver })
	for _, p := range keys {
		in := pairs[p]
		knownKey := "k|" + p.device + "|" + p.resolver
		if _, known := rc.get(knownKey); known {
			continue
		}
		if learning {
			rc.put(knownKey, "1")
			continue
		}
		_, label := rc.label(in.ip)
		how := "plain DNS"
		if in.port == 853 {
			how = "DNS over TLS"
		}
		text := fmt.Sprintf("%s sent %s to %s, which is not an approved resolver: %.0f allowed and %.0f blocked in the last %s. Its lookups then skip your filtering and logs. Some apps and smart devices hardcode a public resolver; if this one is fine, add it under Settings → Network.",
			label, how, p.resolver, in.allowed, in.denied, humanSeconds(rc.value("window_hours")*3600))
		if rc.raise(Finding{
			Title: "DNS bypass from " + label, Description: text, Severity: store.SevLow, Entity: p.device + "|" + p.resolver,
			Source: &event.Endpoint{IP: in.ip}, Destination: &event.Endpoint{IP: p.resolver, Port: in.port},
			Data: map[string]any{"resolver": p.resolver, "port": in.port, "allowed": in.allowed, "blocked": in.denied},
		}) {
			rc.put(knownKey, "1")
		}
	}
	return nil
}

// --- upload spike -------------------------------------------------------------------------

const (
	uploadSettle    = 30 * time.Minute // flows can arrive this long after they start
	maxHourSamples  = 14
	bytesPerMB      = 1e6
	lastHourKey     = "last_hour"
	uploadStateName = "h|"
)

// hourly keeps a device's upload per hour of day, in bytes.
type hourly map[int][]int64

func medianOf(v []int64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s)%2 == 1 {
		return float64(s[len(s)/2])
	}
	return float64(s[len(s)/2-1]+s[len(s)/2]) / 2
}

func runUploadSpike(rc *runCtx) error {
	// The last clock hour that has had time to arrive; once per hour.
	end := rc.now.Add(-uploadSettle).Truncate(time.Hour)
	start := end.Add(-time.Hour)
	if v, ok := rc.get(lastHourKey); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil && !start.After(t) {
			return nil
		}
	}
	rows, err := rc.table("event.module:netflow network.direction:outbound "+internalSources+" | stats sum(network.bytes) as bytes, count as flows by source.ip", start, end)
	if err != nil {
		return err
	}
	rc.put(lastHourKey, start.Format(time.RFC3339))
	learning := rc.learning()
	hour := start.Hour()
	sortRows(rows, func(r row) string { return r.str("source.ip") })
	for _, r := range rows {
		src, ok := rc.home(r.str("source.ip"))
		if !ok {
			continue
		}
		bytes := int64(r.num("bytes"))
		key, label := rc.label(src.String())
		stateKey := uploadStateName + key
		h := hourly{}
		if v, ok := rc.get(stateKey); ok {
			_ = json.Unmarshal([]byte(v), &h)
		}
		samples := h[hour]
		median := medianOf(samples)
		if !learning && float64(len(samples)) >= rc.value("min_samples") &&
			float64(bytes) >= rc.value("min_mb")*bytesPerMB && float64(bytes) >= rc.value("factor")*median {
			rc.reportUpload(src.String(), key, label, bytes, median, len(samples), start, end)
		}
		samples = append(samples, bytes)
		if len(samples) > maxHourSamples {
			samples = samples[len(samples)-maxHourSamples:]
		}
		h[hour] = samples
		if raw, err := json.Marshal(h); err == nil {
			rc.put(stateKey, string(raw))
		}
	}
	return nil
}

func (rc *runCtx) reportUpload(ip, key, label string, bytes int64, median float64, samples int, start, end time.Time) {
	var top []string
	rows, err := rc.table(fmt.Sprintf(`event.module:netflow network.direction:outbound source.ip:%q | stats sum(network.bytes) as bytes by destination.ip | sort 3 -bytes`, ip), start, end)
	if err == nil {
		for _, r := range rows {
			d := fmt.Sprintf("%s (%s)", r.str("destination.ip"), humanBytes(r.num("bytes")))
			if as := rc.asName(r.str("destination.ip")); as != "" {
				d = fmt.Sprintf("%s, %s (%s)", r.str("destination.ip"), as, humanBytes(r.num("bytes")))
			}
			top = append(top, d)
		}
	}
	times := "many"
	if median > 0 {
		times = fmt.Sprintf("%.0f", float64(bytes)/median)
	}
	text := fmt.Sprintf("%s sent %s to the internet between %s and %s UTC, %s times its normal of %s for that hour (from %d earlier samples). Backups and cloud sync can do this, and so can data theft. Top destinations: %s.",
		label, humanBytes(float64(bytes)), start.Format("15:04"), end.Format("15:04"), times, humanBytes(median), samples, strings.Join(top, ", "))
	rc.raise(Finding{
		Title: "Upload spike from " + label, Description: text, Severity: store.SevMedium, Entity: key,
		Source: &event.Endpoint{IP: ip},
		Data:   map[string]any{"bytes": bytes, "normal_bytes": median, "samples": samples, "hour_start": start.Format(time.RFC3339), "top_destinations": top},
	})
}

// --- unusual port -------------------------------------------------------------------------

// usualPorts need no learning.
var usualPorts = []string{"tcp/80", "tcp/443", "udp/443", "udp/123", "udp/53", "tcp/53", "tcp/853"}

func runUnusualPort(rc *runCtx) error {
	from, to := rc.window(rc.value("window_hours"))
	rows, err := rc.table(trafficFilter+" "+internalSources+" "+notBlocked+" NOT destination.ip:10.* NOT destination.ip:192.168.* network.transport:* destination.port:>0 "+
		initiated+" | stats count as n by source.ip, network.transport, destination.port, destination.ip", from, to)
	if err != nil {
		return err
	}
	type use struct {
		ip    string
		count float64
		dests map[string]bool
	}
	uses := map[string]*use{} // device|proto/port
	portOf := map[string]string{}
	for _, r := range rows {
		src, ok := rc.home(r.str("source.ip"))
		dst, ok2 := rc.addr(r.str("destination.ip"))
		if !ok || !ok2 || !rc.scope.Public(dst) {
			continue
		}
		proto, port := r.str("network.transport"), int(r.num("destination.port"))
		if (proto != "tcp" && proto != "udp") || (proto == "udp" && port >= 1024) {
			continue
		}
		pp := proto + "/" + strconv.Itoa(port)
		if contains(usualPorts, pp) || portListed(rc.listOf("allowed_ports"), "", proto, port) {
			continue
		}
		key, _ := rc.label(src.String())
		k := key + "|" + pp
		u := uses[k]
		if u == nil {
			u = &use{ip: src.String(), dests: map[string]bool{}}
			uses[k] = u
			portOf[k] = pp
		}
		u.count += r.num("n")
		u.dests[dst.String()] = true
	}
	learning := rc.learning()
	keys := make([]string, 0, len(uses))
	for k := range uses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// The house's port set grows only after every use in this run has been checked, so
	// two devices starting on a new port in one run are both reported.
	var learned []string
	for _, k := range keys {
		pp := portOf[k]
		houseKey := "p|" + pp
		if _, known := rc.get(houseKey); known {
			continue
		}
		learned = append(learned, houseKey)
		if learning {
			continue
		}
		u := uses[k]
		_, label := rc.label(u.ip)
		dests := make([]string, 0, len(u.dests))
		for d := range u.dests {
			dests = append(dests, d)
		}
		sort.Strings(dests)
		first := dests[0]
		if as := rc.asName(first); as != "" {
			first += ", " + as
		}
		text := fmt.Sprintf("%s connected to the internet on %s, a port no device here has used before: %.0f connections to %d address(es), including %s. Reverse shells and tunnels often use odd ports, and so do some games, VPNs and vendor apps.",
			label, pp, u.count, len(dests), first)
		rc.raise(Finding{
			Title: "Unusual port " + pp + " from " + label, Description: text, Severity: store.SevLow, Entity: k,
			Source: &event.Endpoint{IP: u.ip}, Destination: &event.Endpoint{IP: dests[0]},
			Data: map[string]any{"port": pp, "connections": u.count, "destinations": len(dests)},
		})
	}
	for _, k := range learned {
		rc.put(k, "1")
	}
	return nil
}

// --- internal scan ------------------------------------------------------------------------

func runInternalScan(rc *runCtx) error {
	hours := rc.value("window_minutes") / 60
	from, to := rc.window(hours)
	filter := trafficFilter + " " + internalSources + " " + internalDests
	for _, p := range discoveryPorts {
		filter += " NOT destination.port:" + strconv.Itoa(p)
	}
	allowed := rc.listOf("allowed_scanners")
	// Across hosts. The counts below are a first cut: a source over the threshold is looked at
	// again with its replies taken out.
	rows, err := rc.table(filter+" "+initiated+" | stats count as n by source.ip, destination.ip", from, to)
	if err != nil {
		return err
	}
	hosts := map[string]map[string]bool{}
	for _, r := range rows {
		s, d := r.str("source.ip"), r.str("destination.ip")
		src, ok := rc.home(s)
		dst, ok2 := rc.home(d)
		if !ok || !ok2 || src == dst || contains(allowed, src.String()) {
			continue
		}
		if hosts[s] == nil {
			hosts[s] = map[string]bool{}
		}
		hosts[s][d] = true
	}
	sources := make([]string, 0, len(hosts))
	for s := range hosts {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	minutes := humanSeconds(rc.value("window_minutes") * 60)
	for _, s := range sources {
		if float64(len(hosts[s])) < rc.value("min_hosts") {
			continue
		}
		opened, err := rc.openedFlows(filter, s, "", from, to)
		if err != nil {
			return err
		}
		reached, conns := 0, 0.0
		for d, o := range opened {
			if dst, ok := rc.home(d); ok && dst.String() != s {
				reached++
				conns += o.conns
			}
		}
		if float64(reached) < rc.value("min_hosts") {
			continue
		}
		key, label := rc.label(s)
		text := fmt.Sprintf("%s reached %d other addresses on your network in %s, %.0f connections in all. Scanners and spreading malware do this; so do monitoring tools and network apps. Only traffic crossing the firewall is counted, so the real number can be higher.",
			label, reached, minutes, conns)
		rc.raise(Finding{
			Title: "Internal scan from " + label, Description: text, Severity: store.SevMedium, Entity: key + "|hosts",
			Source: &event.Endpoint{IP: s},
			Data:   map[string]any{"hosts": reached, "connections": conns, "window_minutes": rc.value("window_minutes")},
		})
	}
	// Across the ports of one host.
	rows, err = rc.table(filter+" "+initiated+" | stats dc(destination.port) as ports, count as n by source.ip, destination.ip | sort 2000 -ports", from, to)
	if err != nil {
		return err
	}
	for _, r := range rows {
		s, d := r.str("source.ip"), r.str("destination.ip")
		src, ok := rc.home(s)
		dst, ok2 := rc.home(d)
		if !ok || !ok2 || src == dst || contains(allowed, src.String()) || r.num("ports") < rc.value("min_ports") {
			continue
		}
		opened, err := rc.openedFlows(filter, s, d, from, to)
		if err != nil {
			return err
		}
		o := opened[d]
		if o == nil || float64(len(o.ports)) < rc.value("min_ports") {
			continue
		}
		key, label := rc.label(s)
		_, target := rc.label(d)
		text := fmt.Sprintf("%s tried %d different ports on %s in %s, %.0f connections in all. That is what a port scan looks like; some monitoring tools do it too.",
			label, len(o.ports), target, minutes, o.conns)
		rc.raise(Finding{
			Title: "Port scan from " + label, Description: text, Severity: store.SevMedium, Entity: key + "|ports|" + d,
			Source: &event.Endpoint{IP: s}, Destination: &event.Endpoint{IP: d},
			Data: map[string]any{"ports": float64(len(o.ports)), "connections": o.conns, "window_minutes": rc.value("window_minutes")},
		})
	}
	return nil
}

// opened is what one source started toward one destination.
type opened struct {
	ports map[int]bool
	conns float64
}

// serviceFanOut is how many different ports of its peers one local port must answer before
// it counts as a service port.
const serviceFanOut = 3

// openedFlows returns the connections source s opened, per destination (only d when it is
// set), with replies taken out. The port rule in initiated misses a service whose own port is
// high: its answers to a client's lower ephemeral ports look like connections it started.
// NetFlow records each direction of a conversation, so a TCP record whose reverse record is
// also there is a reply when it carries an ACK and its source port talks to several of the
// peers' ports, the way a service port does. A bare SYN (SYN without ACK) always counts, so
// SYN scans still do whether the target answers or not, and so does a connect scan, which
// uses a new source port for each probe. Firewall rows log the opening packet and are always
// kept, and so are records without flags.
func (rc *runCtx) openedFlows(filter, s, d string, from, to time.Time) (map[string]*opened, error) {
	pair := fmt.Sprintf(" source.ip:%q", s)
	back := fmt.Sprintf("event.module:netflow network.transport:tcp destination.ip:%q ", s)
	if d != "" {
		pair += fmt.Sprintf(" destination.ip:%q", d)
		back += fmt.Sprintf("source.ip:%q", d)
	} else {
		back += internalSources
	}
	rows, err := rc.table(filter+pair+" "+initiated+
		` | eval flags=coalesce(tcp_flags, "-"), proto=coalesce(network.transport, "-")`+
		` | stats count as n by destination.ip, event.module, proto, source.port, destination.port, flags`, from, to)
	if err != nil {
		return nil, err
	}
	reverse := map[string]bool{}
	if len(rows) > 0 {
		revRows, err := rc.table(back+" | stats count as n by source.ip, source.port, destination.port", from, to)
		if err != nil {
			return nil, err
		}
		for _, r := range revRows {
			reverse[fmt.Sprintf("%s|%.0f|%.0f", r.str("source.ip"), r.num("source.port"), r.num("destination.port"))] = true
		}
	}
	isFlow := func(r row) bool { return r.str("event.module") == event.ModuleNetFlow && r.str("proto") == "tcp" }
	fanOut := map[float64]map[string]bool{} // source port -> peer ip|port
	for _, r := range rows {
		if isFlow(r) {
			sp := r.num("source.port")
			if fanOut[sp] == nil {
				fanOut[sp] = map[string]bool{}
			}
			fanOut[sp][fmt.Sprintf("%s|%.0f", r.str("destination.ip"), r.num("destination.port"))] = true
		}
	}
	out := map[string]*opened{}
	for _, r := range rows {
		dst, sport, dport := r.str("destination.ip"), r.num("source.port"), r.num("destination.port")
		if isFlow(r) && reverse[fmt.Sprintf("%s|%.0f|%.0f", dst, dport, sport)] {
			f := strings.TrimPrefix(r.str("flags"), "-")
			bareSYN := strings.Contains(f, "S") && !strings.Contains(f, "A")
			if f != "" && !bareSYN && len(fanOut[sport]) >= serviceFanOut {
				continue // a service answering clients it did not call
			}
		}
		o := out[dst]
		if o == nil {
			o = &opened{ports: map[int]bool{}}
			out[dst] = o
		}
		o.ports[int(dport)] = true
		o.conns += r.num("n")
	}
	return out, nil
}

// --- rogue DHCP ---------------------------------------------------------------------------

func runRogueDHCP(rc *runCtx) error {
	from, to := rc.window(rc.value("window_hours"))
	rows, err := rc.table("source.port:67 destination.port:68 | stats count as n, dc(destination.ip) as clients by source.ip", from, to)
	if err != nil {
		return err
	}
	learning := rc.learning()
	approved := rc.listOf("approved_servers")
	sortRows(rows, func(r row) string { return r.str("source.ip") })
	for _, r := range rows {
		ip := r.str("source.ip")
		src, ok := rc.home(ip) // the firewall is not "home", so it never gets here
		if !ok || contains(approved, src.String()) {
			continue
		}
		key, label := rc.label(src.String())
		knownKey := "k|" + src.String()
		if _, known := rc.get(knownKey); known {
			continue
		}
		if learning {
			rc.put(knownKey, "1")
			continue
		}
		text := fmt.Sprintf("%s answered DHCP %.0f times in the last %s. Only your firewall should. A second DHCP server can hand out a hostile gateway or DNS server, or it may just be a travel router or access point plugged in the wrong way. If it is meant to be there, add it under Settings → Network.",
			label, r.num("n"), humanSeconds(rc.value("window_hours")*3600))
		if rc.raise(Finding{
			Title: "Unexpected DHCP server: " + label, Description: text, Severity: store.SevMedium, Entity: key,
			Source: &event.Endpoint{IP: src.String(), Port: 67},
			Data:   map[string]any{"replies": r.num("n"), "clients": r.num("clients")},
		}) {
			rc.put(knownKey, "1")
		}
	}
	return nil
}

// --- exposure -----------------------------------------------------------------------------

func runExposure(rc *runCtx) error {
	from, to := rc.window(rc.value("window_hours"))
	group := " | stats count as n by source.ip, destination.ip, destination.port, network.transport"
	// A firewall logs the packet that opens a connection, so an allowed row from a public
	// address to an internal one is a connection coming in.
	rows, err := rc.table("event.module:opnsense event.action:pass network.direction:inbound "+internalDests+group, from, to)
	if err != nil {
		return err
	}
	// NetFlow also has every reply coming back, so only count what cannot be a reply: TCP to
	// a low port, from a higher one.
	flows, err := rc.table("event.module:netflow network.direction:inbound network.transport:tcp destination.port:<1024 "+internalDests+" "+initiated+group, from, to)
	if err != nil {
		return err
	}
	rows = append(rows, flows...)
	type service struct {
		ip, proto string
		port      int
		count     float64
		sources   map[string]bool
	}
	services := map[string]*service{}
	for _, r := range rows {
		src, ok := rc.addr(r.str("source.ip"))
		dst, ok2 := rc.home(r.str("destination.ip"))
		if !ok || !ok2 || !rc.scope.Public(src) {
			continue
		}
		proto, port := r.str("network.transport"), int(r.num("destination.port"))
		if port == 0 || (proto != "tcp" && proto != "udp") || portListed(rc.listOf("expected"), dst.String(), proto, port) {
			continue
		}
		key, _ := rc.label(dst.String())
		k := fmt.Sprintf("%s|%s/%d", key, proto, port)
		s := services[k]
		if s == nil {
			s = &service{ip: dst.String(), proto: proto, port: port, sources: map[string]bool{}}
			services[k] = s
		}
		s.count += r.num("n")
		s.sources[src.String()] = true
	}
	learning := rc.learning()
	keys := make([]string, 0, len(services))
	for k := range services {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		knownKey := "k|" + k
		if _, known := rc.get(knownKey); known {
			continue
		}
		if learning {
			rc.put(knownKey, "1")
			continue
		}
		s := services[k]
		_, label := rc.label(s.ip)
		list := make([]string, 0, len(s.sources))
		for a := range s.sources {
			list = append(list, a)
		}
		sort.Strings(list)
		text := fmt.Sprintf("The internet can reach %s on %s/%d: %.0f allowed connections from %d public address(es), including %s, in the last %s. Check whether you opened this on purpose, with a port forward, or something opened it with UPnP. If it is expected, add it under Settings → Network.",
			label, s.proto, s.port, s.count, len(list), list[0], humanSeconds(rc.value("window_hours")*3600))
		if rc.raise(Finding{
			Title: fmt.Sprintf("Service exposed to the internet: %s %s/%d", label, s.proto, s.port), Description: text, Severity: store.SevMedium, Entity: k,
			Source: &event.Endpoint{IP: list[0]}, Destination: &event.Endpoint{IP: s.ip, Port: s.port},
			Data: map[string]any{"connections": s.count, "public_sources": len(list), "port": s.port, "transport": s.proto},
		}) {
			rc.put(knownKey, "1")
		}
	}
	return nil
}

// --- text helpers -------------------------------------------------------------------------

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func round(v float64) float64 { return math.Round(v) }

func roundTo(v float64, places int) float64 {
	m := math.Pow10(places)
	return math.Round(v*m) / m
}

func humanSeconds(s float64) string {
	switch {
	case s < 90:
		return fmt.Sprintf("%.0f seconds", s)
	case s < 90*60:
		return fmt.Sprintf("%.0f minutes", s/60)
	case s < 48*3600:
		return fmt.Sprintf("%.1f hours", s/3600)
	}
	return fmt.Sprintf("%.1f days", s/86400)
}

func humanBytes(b float64) string {
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.1f GB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.0f MB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.0f kB", b/1e3)
	}
	return fmt.Sprintf("%.0f bytes", b)
}
