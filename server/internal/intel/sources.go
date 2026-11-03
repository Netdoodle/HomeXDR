package intel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Key requirements of a provider.
const (
	KeyNone     = "none"     // no key exists
	KeyOptional = "optional" // works without one, with a lower quota
	KeyRequired = "required"
)

// Provider is a service with its own on/off switch and API key. Most have one source;
// abuse.ch has three behind one key.
type Provider struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	About  string   `json:"about"`
	Key    string   `json:"key_mode"`
	KeyURL string   `json:"key_url,omitempty"` // where to get a free key
	Free   string   `json:"free,omitempty"`    // the free quota
	Kinds  []string `json:"kinds"`
}

// Source answers lookups for some indicator kinds.
type Source struct {
	ID, Name, Provider string
	Kinds              []string
	// Weight is how much the source's risk counts in the score (0: context only).
	Weight int
	Lookup func(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error)
}

// Providers lists every provider.
var Providers = []Provider{
	{ID: "virustotal", Name: "VirusTotal", About: "Verdicts from about 90 antivirus engines and URL scanners.", Key: KeyRequired,
		KeyURL: "https://www.virustotal.com/gui/my-apikey", Free: "4 lookups a minute, 500 a day", Kinds: []string{KindIP, KindDomain, KindURL, KindHash}},
	{ID: "abuseipdb", Name: "AbuseIPDB", About: "Community reports of abusive IP addresses.", Key: KeyRequired,
		KeyURL: "https://www.abuseipdb.com/account/api", Free: "1,000 lookups a day", Kinds: []string{KindIP}},
	{ID: "abusech", Name: "abuse.ch", About: "URLhaus (malware URLs), MalwareBazaar (malware samples) and ThreatFox (IOCs), with one key.", Key: KeyRequired,
		KeyURL: "https://auth.abuse.ch/", Free: "Free key, fair use", Kinds: []string{KindIP, KindDomain, KindURL, KindHash}},
	{ID: "otx", Name: "AlienVault OTX", About: "Community threat reports (pulses).", Key: KeyOptional,
		KeyURL: "https://otx.alienvault.com/api", Kinds: []string{KindIP, KindDomain, KindURL, KindHash}},
	{ID: "greynoise", Name: "GreyNoise", About: "Whether an IP scans the internet, and whether that looks malicious.", Key: KeyOptional,
		KeyURL: "https://viz.greynoise.io/account/api-key", Free: "Limited lookups a day without a key", Kinds: []string{KindIP}},
	{ID: "pulsedive", Name: "Pulsedive", About: "Risk rating, threats and feeds that list the indicator.", Key: KeyOptional,
		KeyURL: "https://pulsedive.com/account", Kinds: []string{KindIP, KindDomain, KindURL}},
	{ID: "urlscan", Name: "urlscan.io", About: "Public website scans: hosting, TLS and domain age.", Key: KeyOptional,
		KeyURL: "https://urlscan.io/user/profile/", Kinds: []string{KindIP, KindDomain, KindURL}},
	{ID: "proxycheck", Name: "ProxyCheck", About: "Whether an IP is a VPN, proxy or Tor exit.", Key: KeyOptional,
		KeyURL: "https://proxycheck.io/dashboard/", Free: "100 lookups a day without a key", Kinds: []string{KindIP}},
	{ID: "circl", Name: "CIRCL hashlookup", About: "Known files, from software distributions and NSRL.", Key: KeyNone, Kinds: []string{KindHash}},
	{ID: "internetdb", Name: "Shodan InternetDB", About: "Open ports, hostnames and known CVEs.", Key: KeyNone, Kinds: []string{KindIP}},
	{ID: "ipwho", Name: "ipwho.is", About: "Location and network of an IP.", Key: KeyNone, Kinds: []string{KindIP}},
	{ID: "rdap", Name: "WHOIS (RDAP)", About: "Registration data for IP networks and domains.", Key: KeyNone, Kinds: []string{KindIP, KindDomain}},
}

// Sources lists every source, in the order results are shown.
var Sources = []Source{
	{ID: "virustotal", Name: "VirusTotal", Provider: "virustotal", Kinds: []string{KindIP, KindDomain, KindURL, KindHash}, Weight: 3, Lookup: lookupVirusTotal},
	{ID: "abuseipdb", Name: "AbuseIPDB", Provider: "abuseipdb", Kinds: []string{KindIP}, Weight: 3, Lookup: lookupAbuseIPDB},
	{ID: "malwarebazaar", Name: "MalwareBazaar", Provider: "abusech", Kinds: []string{KindHash}, Weight: 3, Lookup: lookupMalwareBazaar},
	{ID: "urlhaus", Name: "URLhaus", Provider: "abusech", Kinds: []string{KindIP, KindDomain, KindURL, KindHash}, Weight: 3, Lookup: lookupURLhaus},
	{ID: "threatfox", Name: "ThreatFox", Provider: "abusech", Kinds: []string{KindIP, KindDomain, KindURL, KindHash}, Weight: 3, Lookup: lookupThreatFox},
	{ID: "greynoise", Name: "GreyNoise", Provider: "greynoise", Kinds: []string{KindIP}, Weight: 2, Lookup: lookupGreyNoise},
	{ID: "circl", Name: "CIRCL hashlookup", Provider: "circl", Kinds: []string{KindHash}, Weight: 2, Lookup: lookupCIRCL},
	{ID: "otx", Name: "AlienVault OTX", Provider: "otx", Kinds: []string{KindIP, KindDomain, KindURL, KindHash}, Weight: 1, Lookup: lookupOTX},
	{ID: "pulsedive", Name: "Pulsedive", Provider: "pulsedive", Kinds: []string{KindIP, KindDomain, KindURL}, Weight: 1, Lookup: lookupPulsedive},
	{ID: "internetdb", Name: "Shodan InternetDB", Provider: "internetdb", Kinds: []string{KindIP}, Weight: 1, Lookup: lookupInternetDB},
	{ID: "proxycheck", Name: "ProxyCheck", Provider: "proxycheck", Kinds: []string{KindIP}, Lookup: lookupProxyCheck},
	{ID: "urlscan", Name: "urlscan.io", Provider: "urlscan", Kinds: []string{KindIP, KindDomain, KindURL}, Lookup: lookupURLScan},
	{ID: "ipwho", Name: "ipwho.is", Provider: "ipwho", Kinds: []string{KindIP}, Lookup: lookupIPWho},
	{ID: "rdap", Name: "WHOIS (RDAP)", Provider: "rdap", Kinds: []string{KindIP, KindDomain}, Lookup: lookupRDAP},
}

func providerByID(id string) *Provider {
	for i := range Providers {
		if Providers[i].ID == id {
			return &Providers[i]
		}
	}
	return nil
}

// Result states.
const (
	StateOK       = "ok"        // the source knows the indicator
	StateNoData   = "no_data"   // it answered and has nothing
	StateNeedsKey = "needs_key" // it needs an API key that is not set
	StateQuota    = "quota"     // over its quota
	StateError    = "error"
	StatePending  = "pending"
)

// Result is one source's answer.
type Result struct {
	Source    string    `json:"source"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	Message   string    `json:"message,omitempty"` // why there is no data
	CheckedAt time.Time `json:"checked_at"`
	// Risk is 0-100 for sources with a reputation signal; nil is context only.
	Risk     *int     `json:"risk,omitempty"`
	Headline string   `json:"headline,omitempty"`
	Fields   []Field  `json:"fields,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Link     string   `json:"link,omitempty"` // the indicator on the source's site
	// Benign says the source vouches for the indicator (a known file, an allowlist).
	Benign bool   `json:"benign,omitempty"`
	Geo    *Geo   `json:"geo,omitempty"`
	Whois  *Whois `json:"whois,omitempty"`
	// DomainAgeDays is how long ago a domain was registered, where the source knows.
	DomainAgeDays *int `json:"domain_age_days,omitempty"`
}

// Field is one labeled value in a source's answer.
type Field struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Geo locates an IP address.
type Geo struct {
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	City        string  `json:"city,omitempty"`
	Region      string  `json:"region,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	Org         string  `json:"org,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
}

// Whois is registration data for an IP network or domain.
type Whois struct {
	Registrant string   `json:"registrant,omitempty"`
	Registrar  string   `json:"registrar,omitempty"`
	NetName    string   `json:"net_name,omitempty"`
	Range      string   `json:"range,omitempty"`
	Created    string   `json:"created,omitempty"`
	Updated    string   `json:"updated,omitempty"`
	Expires    string   `json:"expires,omitempty"`
	Abuse      string   `json:"abuse,omitempty"`
	NameServer []string `json:"name_servers,omitempty"`
}

func (r *Result) add(label, value string) {
	if value = strings.TrimSpace(value); value != "" {
		r.Fields = append(r.Fields, Field{Label: label, Value: trimText(value, 300)})
	}
}

func (r *Result) addInt(label string, v int) { r.add(label, strconv.Itoa(v)) }

func (r *Result) risk(v int) {
	v = min(max(v, 0), 100)
	r.Risk = &v
}

func trimText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// firstN joins up to n values, saying how many more there are.
func firstN(vals []string, n int) string {
	if len(vals) <= n {
		return strings.Join(vals, ", ")
	}
	return strings.Join(vals[:n], ", ") + fmt.Sprintf(" and %d more", len(vals)-n)
}

func uniq(vals []string) []string {
	seen := map[string]bool{}
	out := vals[:0:0]
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" && !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	return out
}

// dateOf shortens a timestamp to its date.
func dateOf(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 10 && s[4] == '-' && s[7] == '-' {
		return s[:10]
	}
	return s
}

func unixDate(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.DateOnly)
}

// Lookup failures a source reports.
var (
	errNoData = errors.New("no data")
	errQuota  = errors.New("over quota")
	errBadKey = errors.New("the service refused the API key")
)

// noData is a no-data answer with a reason.
func noData(msg string) error { return fmt.Errorf("%w: %s", errNoData, msg) }

// maxResponse caps what is read from a service.
const maxResponse = 8 << 20

// fetcher makes requests to the intelligence services. Only fixed service URLs are ever
// requested: the indicator itself is never visited.
type fetcher struct {
	client *http.Client
}

func (f *fetcher) do(req *http.Request, hdr map[string]string, out any) error {
	req.Header.Set("User-Agent", "homexdr-intel")
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) { // the URL can hold an API key parameter
			err = ue.Err
		}
		return fmt.Errorf("could not reach %s: %w", req.URL.Hostname(), err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
	case http.StatusNotFound, http.StatusNoContent:
		return errNoData
	case http.StatusTooManyRequests, http.StatusPaymentRequired:
		return errQuota
	case http.StatusUnauthorized, http.StatusForbidden:
		return errBadKey
	default:
		return fmt.Errorf("%s answered HTTP %d", req.URL.Hostname(), resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("read %s: %w", req.URL.Hostname(), err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s sent an unexpected answer", req.URL.Hostname())
	}
	return nil
}

func (f *fetcher) get(ctx context.Context, u string, hdr map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return f.do(req, hdr, out)
}

func (f *fetcher) postForm(ctx context.Context, u string, form url.Values, hdr map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(req, hdr, out)
}

func (f *fetcher) postJSON(ctx context.Context, u string, in any, hdr map[string]string, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return f.do(req, hdr, out)
}

// --- VirusTotal --------------------------------------------------------------------------------

// vtRisk maps flagging engines to a risk. One engine is routinely wrong (8.8.8.8 usually has
// one), so it barely counts.
func vtRisk(malicious, suspicious int) int {
	hits := float64(malicious) + float64(suspicious)/2
	switch {
	case hits <= 0:
		return 0
	case hits < 2:
		return 10
	case hits < 3:
		return 30
	case hits < 5:
		return 50
	case hits < 10:
		return 75
	case hits < 20:
		return 90
	}
	return 100
}

func lookupVirusTotal(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	var path string
	switch ind.Kind {
	case KindIP:
		path = "ip_addresses/" + url.PathEscape(ind.Value)
	case KindDomain:
		path = "domains/" + url.PathEscape(ind.Value)
	case KindHash:
		path = "files/" + ind.Value
	case KindURL:
		path = "urls/" + base64.RawURLEncoding.EncodeToString([]byte(ind.Value))
	}
	var resp struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
					Timeout    int `json:"timeout"`
				} `json:"last_analysis_stats"`
				Reputation     int      `json:"reputation"`
				LastAnalysis   int64    `json:"last_analysis_date"`
				Created        int64    `json:"creation_date"`
				Tags           []string `json:"tags"`
				MeaningfulName string   `json:"meaningful_name"`
				TypeDesc       string   `json:"type_description"`
				Size           int64    `json:"size"`
				ASOwner        string   `json:"as_owner"`
				Country        string   `json:"country"`
				Registrar      string   `json:"registrar"`
				Classification struct {
					Label string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := f.get(ctx, "https://www.virustotal.com/api/v3/"+path, map[string]string{"x-apikey": key}, &resp); err != nil {
		return nil, err
	}
	a := resp.Data.Attributes
	s := a.Stats
	total := s.Malicious + s.Suspicious + s.Harmless + s.Undetected + s.Timeout
	if total == 0 {
		return nil, noData("not analyzed yet")
	}
	r := &Result{Link: "https://www.virustotal.com/gui/search/" + url.PathEscape(ind.Value), Tags: a.Tags}
	r.risk(vtRisk(s.Malicious, s.Suspicious))
	r.Headline = fmt.Sprintf("%d of %d engines flag it", s.Malicious+s.Suspicious, total)
	r.addInt("Malicious", s.Malicious)
	r.addInt("Suspicious", s.Suspicious)
	r.addInt("Harmless", s.Harmless)
	r.addInt("Undetected", s.Undetected)
	r.addInt("Community score", a.Reputation)
	r.add("Threat label", a.Classification.Label)
	r.add("File name", a.MeaningfulName)
	r.add("File type", a.TypeDesc)
	if a.Size > 0 {
		r.add("File size", strconv.FormatInt(a.Size, 10)+" bytes")
	}
	r.add("Network", a.ASOwner)
	r.add("Country", a.Country)
	r.add("Registrar", a.Registrar)
	r.add("Last analysis", unixDate(a.LastAnalysis))
	if ind.Kind == KindDomain && a.Created > 0 {
		r.add("Registered", unixDate(a.Created))
		days := int(time.Since(time.Unix(a.Created, 0)).Hours() / 24)
		r.DomainAgeDays = &days
	}
	return r, nil
}

// --- AbuseIPDB ---------------------------------------------------------------------------------

func lookupAbuseIPDB(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	var resp struct {
		Data struct {
			Score       int    `json:"abuseConfidenceScore"`
			Reports     int    `json:"totalReports"`
			Reporters   int    `json:"numDistinctUsers"`
			Last        string `json:"lastReportedAt"`
			Usage       string `json:"usageType"`
			ISP         string `json:"isp"`
			Domain      string `json:"domain"`
			Country     string `json:"countryCode"`
			Whitelisted *bool  `json:"isWhitelisted"`
			Tor         bool   `json:"isTor"`
		} `json:"data"`
	}
	u := "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + url.QueryEscape(ind.Value)
	if err := f.get(ctx, u, map[string]string{"Key": key}, &resp); err != nil {
		return nil, err
	}
	d := resp.Data
	r := &Result{Link: "https://www.abuseipdb.com/check/" + ind.Value}
	r.risk(d.Score)
	r.Headline = fmt.Sprintf("Abuse confidence %d%%, %d reports in 90 days", d.Score, d.Reports)
	r.addInt("Abuse confidence", d.Score)
	r.addInt("Reports", d.Reports)
	r.addInt("Reporters", d.Reporters)
	r.add("Last reported", dateOf(d.Last))
	r.add("Usage", d.Usage)
	r.add("ISP", d.ISP)
	r.add("Domain", d.Domain)
	r.add("Country", d.Country)
	if d.Tor {
		r.Tags = append(r.Tags, "tor")
	}
	if d.Whitelisted != nil && *d.Whitelisted {
		r.Tags = append(r.Tags, "allowlisted")
		r.Benign = true
	}
	return r, nil
}

// --- abuse.ch ----------------------------------------------------------------------------------

func lookupURLhaus(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	endpoint, form := "host", url.Values{}
	switch ind.Kind {
	case KindIP, KindDomain:
		form.Set("host", ind.Value)
	case KindURL:
		endpoint = "url"
		form.Set("url", ind.Value)
	case KindHash:
		endpoint = "payload"
		switch ind.HashType {
		case "md5":
			form.Set("md5_hash", ind.Value)
		case "sha256":
			form.Set("sha256_hash", ind.Value)
		default:
			return nil, noData("URLhaus only looks up MD5 and SHA-256 hashes")
		}
	}
	var resp struct {
		Status    string `json:"query_status"`
		Reference string `json:"urlhaus_reference"`
		// host and payload lookups
		URLCount  json.Number `json:"url_count"`
		FirstSeen string      `json:"firstseen"`
		LastSeen  string      `json:"lastseen"`
		URLs      []struct {
			Status string   `json:"url_status"`
			Threat string   `json:"threat"`
			Tags   []string `json:"tags"`
		} `json:"urls"`
		// url lookups
		URLStatus string   `json:"url_status"`
		Threat    string   `json:"threat"`
		DateAdded string   `json:"date_added"`
		Tags      []string `json:"tags"`
		// payload lookups
		FileType  string `json:"file_type"`
		Signature string `json:"signature"`
	}
	if err := f.postForm(ctx, "https://urlhaus-api.abuse.ch/v1/"+endpoint+"/", form, map[string]string{"Auth-Key": key}, &resp); err != nil {
		return nil, err
	}
	if resp.Status != "ok" {
		return nil, errNoData
	}
	r := &Result{Link: resp.Reference}
	online, threats, tags := 0, []string{resp.Threat}, resp.Tags
	for _, u := range resp.URLs {
		if u.Status == "online" {
			online++
		}
		threats = append(threats, u.Threat)
		tags = append(tags, u.Tags...)
	}
	if resp.URLStatus == "online" {
		online = 1
	}
	r.Tags = uniq(tags)
	switch {
	case ind.Kind == KindHash:
		r.risk(90)
		r.Headline = "Listed as a malware payload"
	case online > 0:
		r.risk(95)
		r.Headline = "Serving malware now"
	default:
		r.risk(65)
		r.Headline = "Has served malware (now offline)"
	}
	r.add("URLs listed", resp.URLCount.String())
	if ind.Kind != KindURL && len(resp.URLs) > 0 {
		r.addInt("Still online", online)
	}
	r.add("Status", resp.URLStatus)
	r.add("Threat", firstN(uniq(threats), 3))
	r.add("Signature", resp.Signature)
	r.add("File type", resp.FileType)
	r.add("First seen", dateOf(resp.FirstSeen+resp.DateAdded))
	r.add("Last seen", dateOf(resp.LastSeen))
	return r, nil
}

func lookupMalwareBazaar(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	var resp struct {
		Status string `json:"query_status"`
		Data   []struct {
			SHA256    string   `json:"sha256_hash"`
			FileName  string   `json:"file_name"`
			FileType  string   `json:"file_type"`
			Signature string   `json:"signature"`
			FirstSeen string   `json:"first_seen"`
			LastSeen  string   `json:"last_seen"`
			Delivery  string   `json:"delivery_method"`
			Tags      []string `json:"tags"`
		} `json:"data"`
	}
	form := url.Values{"query": {"get_info"}, "hash": {ind.Value}}
	if err := f.postForm(ctx, "https://mb-api.abuse.ch/api/v1/", form, map[string]string{"Auth-Key": key}, &resp); err != nil {
		return nil, err
	}
	if resp.Status != "ok" || len(resp.Data) == 0 {
		return nil, errNoData
	}
	d := resp.Data[0]
	r := &Result{Link: "https://bazaar.abuse.ch/sample/" + d.SHA256 + "/", Tags: uniq(d.Tags)}
	r.risk(100)
	r.Headline = "Known malware sample"
	if d.Signature != "" {
		r.Headline += ": " + d.Signature
	}
	r.add("Family", d.Signature)
	r.add("File name", d.FileName)
	r.add("File type", d.FileType)
	r.add("Delivery", d.Delivery)
	r.add("First seen", dateOf(d.FirstSeen))
	r.add("Last seen", dateOf(d.LastSeen))
	return r, nil
}

func lookupThreatFox(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	query := map[string]any{"query": "search_ioc", "search_term": ind.Value}
	if ind.Kind == KindHash {
		query = map[string]any{"query": "search_hash", "hash": ind.Value}
	}
	var resp struct {
		Status string          `json:"query_status"`
		Data   json.RawMessage `json:"data"` // a list, or a string when nothing matched
	}
	if err := f.postJSON(ctx, "https://threatfox-api.abuse.ch/api/v1/", query, map[string]string{"Auth-Key": key}, &resp); err != nil {
		return nil, err
	}
	var hits []struct {
		Threat     string   `json:"threat_type_desc"`
		Malware    string   `json:"malware_printable"`
		Confidence int      `json:"confidence_level"`
		FirstSeen  string   `json:"first_seen"`
		LastSeen   string   `json:"last_seen"`
		Tags       []string `json:"tags"`
	}
	if resp.Status != "ok" || json.Unmarshal(resp.Data, &hits) != nil || len(hits) == 0 {
		return nil, errNoData
	}
	r := &Result{Link: "https://threatfox.abuse.ch/browse.php?search=ioc%3A" + url.QueryEscape(ind.Value)}
	conf := 0
	var malware, threats, tags []string
	for _, h := range hits {
		conf = max(conf, h.Confidence)
		malware, threats = append(malware, h.Malware), append(threats, h.Threat)
		tags = append(tags, h.Tags...)
	}
	r.risk(max(70, conf))
	r.Tags = uniq(tags)
	r.Headline = "Reported IOC: " + firstN(uniq(malware), 2)
	r.addInt("Reports", len(hits))
	r.add("Malware", firstN(uniq(malware), 5))
	r.add("Threat", firstN(uniq(threats), 3))
	r.addInt("Confidence", conf)
	r.add("First seen", dateOf(hits[0].FirstSeen))
	r.add("Last seen", dateOf(hits[0].LastSeen))
	return r, nil
}

// --- GreyNoise ---------------------------------------------------------------------------------

func lookupGreyNoise(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	var resp struct {
		Noise          bool   `json:"noise"`
		RIOT           bool   `json:"riot"`
		Classification string `json:"classification"`
		Name           string `json:"name"`
		Link           string `json:"link"`
		LastSeen       string `json:"last_seen"`
	}
	if err := f.get(ctx, "https://api.greynoise.io/v3/community/"+url.PathEscape(ind.Value), map[string]string{"key": key}, &resp); err != nil {
		if errors.Is(err, errNoData) {
			return nil, noData("not observed scanning the internet")
		}
		return nil, err
	}
	r := &Result{Link: resp.Link}
	switch {
	case resp.RIOT:
		r.risk(0)
		r.Benign = true
		r.Headline = "Known business service"
	case resp.Classification == "malicious":
		r.risk(85)
		r.Headline = "Classified as malicious"
	case resp.Classification == "suspicious":
		r.risk(55)
		r.Headline = "Classified as suspicious"
	case resp.Classification == "benign":
		r.risk(0)
		r.Benign = true
		r.Headline = "Classified as benign"
	default:
		r.risk(20)
		r.Headline = "Scans the internet, intent unknown"
	}
	r.add("Classification", resp.Classification)
	if resp.Name != "unknown" {
		r.add("Name", resp.Name)
	}
	if resp.Noise {
		r.Tags = append(r.Tags, "internet scanner")
	}
	r.add("Last seen", resp.LastSeen)
	return r, nil
}

// --- CIRCL hashlookup --------------------------------------------------------------------------

func lookupCIRCL(ctx context.Context, f *fetcher, ind Indicator, _ string) (*Result, error) {
	var resp struct {
		FileName string `json:"FileName"`
		Size     string `json:"FileSize"`
		Product  struct {
			Name    string `json:"ProductName"`
			Version string `json:"ProductVersion"`
			Vendor  string `json:"MfgCode"`
		} `json:"ProductCode"`
		Trust     int    `json:"hashlookup:trust"`
		Source    string `json:"source"`
		Malicious any    `json:"KnownMalicious"`
	}
	if err := f.get(ctx, "https://hashlookup.circl.lu/lookup/"+ind.HashType+"/"+ind.Value, nil, &resp); err != nil {
		if errors.Is(err, errNoData) {
			return nil, noData("not a known file")
		}
		return nil, err
	}
	r := &Result{Link: "https://hashlookup.circl.lu/lookup/" + ind.HashType + "/" + ind.Value}
	if resp.Malicious != nil {
		r.risk(90)
		r.Headline = "Listed as known malicious"
	} else {
		r.risk(0)
		r.Benign = resp.Trust >= 50
		r.Headline = "Known file"
		if resp.Product.Name != "" {
			r.Headline += " from " + resp.Product.Name
		}
	}
	r.add("File name", resp.FileName)
	r.add("Product", strings.TrimSpace(resp.Product.Name+" "+resp.Product.Version))
	r.add("Source", resp.Source)
	if resp.Trust > 0 {
		r.addInt("Trust", resp.Trust)
	}
	return r, nil
}

// --- AlienVault OTX ----------------------------------------------------------------------------

// otxBenign are OTX validation sources that vouch for an indicator.
var otxBenign = map[string]bool{"whitelist": true, "false_positive": true, "majestic": true, "alexa": true, "akamai": true}

// otxRisk reads pulse counts cautiously: popular infrastructure collects pulses too, and
// old reports say little about now.
func otxRisk(pulses int, newest time.Time, now time.Time) int {
	risk := 60
	switch {
	case pulses < 3:
		risk = 20
	case pulses < 10:
		risk = 40
	}
	if now.Sub(newest) > 180*24*time.Hour {
		risk /= 2
	}
	return risk
}

func lookupOTX(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	section := map[string]string{KindIP: "IPv4", KindDomain: "domain", KindURL: "url", KindHash: "file"}[ind.Kind]
	page := map[string]string{KindIP: "ip", KindDomain: "domain", KindURL: "url", KindHash: "file"}[ind.Kind]
	if ind.Kind == KindIP && strings.Contains(ind.Value, ":") {
		section = "IPv6"
	}
	var resp struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name     string   `json:"name"`
				Modified string   `json:"modified"`
				Tags     []string `json:"tags"`
				Families []struct {
					Name string `json:"display_name"`
				} `json:"malware_families"`
			} `json:"pulses"`
		} `json:"pulse_info"`
		Validation []struct {
			Source string `json:"source"`
		} `json:"validation"`
	}
	u := "https://otx.alienvault.com/api/v1/indicators/" + section + "/" + url.PathEscape(ind.Value) + "/general"
	if err := f.get(ctx, u, map[string]string{"X-OTX-API-KEY": key}, &resp); err != nil {
		return nil, err
	}
	r := &Result{Link: "https://otx.alienvault.com/indicator/" + page + "/" + url.PathEscape(ind.Value)}
	for _, v := range resp.Validation {
		if otxBenign[v.Source] {
			r.Benign = true
		}
		if v.Source == "tor_exits" {
			r.Tags = append(r.Tags, "tor")
		}
	}
	p := resp.PulseInfo
	if p.Count == 0 {
		if r.Benign {
			r.risk(0)
			r.Headline = "On an allowlist, no threat reports"
			return r, nil
		}
		return nil, noData("no threat reports")
	}
	var newest time.Time
	var names, families, tags []string
	for _, pulse := range p.Pulses {
		if t, err := time.Parse("2006-01-02T15:04:05", strings.SplitN(pulse.Modified, ".", 2)[0]); err == nil && t.After(newest) {
			newest = t
		}
		names = append(names, pulse.Name)
		tags = append(tags, pulse.Tags...)
		for _, fam := range pulse.Families {
			families = append(families, fam.Name)
		}
	}
	if r.Benign {
		r.risk(0)
		r.Headline = fmt.Sprintf("On an allowlist (mentioned in %d reports)", p.Count)
	} else {
		r.risk(otxRisk(p.Count, newest, time.Now()))
		r.Headline = fmt.Sprintf("In %d threat reports", p.Count)
	}
	r.addInt("Pulses", p.Count)
	if !newest.IsZero() {
		r.add("Last report", newest.Format(time.DateOnly))
	}
	r.add("Malware", firstN(uniq(families), 5))
	r.add("Reports", firstN(uniq(names), 3))
	if t := uniq(tags); len(t) > 8 {
		r.Tags = append(r.Tags, t[:8]...)
	} else {
		r.Tags = append(r.Tags, t...)
	}
	return r, nil
}

// --- Pulsedive ---------------------------------------------------------------------------------

var pulsediveRisk = map[string]int{"none": 0, "low": 25, "medium": 50, "high": 75, "critical": 95}

func lookupPulsedive(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	q := url.Values{"indicator": {ind.Value}, "pretty": {"0"}}
	if key != "" {
		q.Set("key", key)
	}
	var resp struct {
		IID     int64  `json:"iid"`
		Risk    string `json:"risk"`
		Error   string `json:"error"`
		Seen    string `json:"stamp_seen"`
		Retired any    `json:"retired"`
		Factors []struct {
			Description string `json:"description"`
		} `json:"riskfactors"`
		Threats []struct {
			Name string `json:"name"`
		} `json:"threats"`
		Feeds []struct {
			Name string `json:"name"`
		} `json:"feeds"`
	}
	if err := f.get(ctx, "https://pulsedive.com/api/info.php?"+q.Encode(), nil, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" || resp.IID == 0 {
		return nil, errNoData
	}
	r := &Result{Link: fmt.Sprintf("https://pulsedive.com/indicator/?iid=%d", resp.IID)}
	if v, ok := pulsediveRisk[resp.Risk]; ok {
		r.risk(v)
	}
	r.Headline = "Risk rating: " + resp.Risk
	r.add("Risk", resp.Risk)
	var names []string
	for _, t := range resp.Threats {
		names = append(names, t.Name)
	}
	r.add("Threats", firstN(uniq(names), 5))
	names = nil
	for _, t := range resp.Feeds {
		names = append(names, t.Name)
	}
	r.add("Feeds", firstN(uniq(names), 5))
	names = nil
	for _, t := range resp.Factors {
		names = append(names, t.Description)
	}
	r.add("Risk factors", firstN(uniq(names), 4))
	r.add("Last seen", dateOf(resp.Seen))
	if resp.Retired != nil {
		r.Tags = append(r.Tags, "retired")
	}
	return r, nil
}

// --- Shodan InternetDB -------------------------------------------------------------------------

// internetDBBad are InternetDB tags that say the host itself is hostile or compromised.
var internetDBBad = map[string]bool{"malware": true, "c2": true, "compromised": true, "doublepulsar": true}

func lookupInternetDB(ctx context.Context, f *fetcher, ind Indicator, _ string) (*Result, error) {
	var resp struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		CPEs      []string `json:"cpes"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
	}
	if err := f.get(ctx, "https://internetdb.shodan.io/"+url.PathEscape(ind.Value), nil, &resp); err != nil {
		if errors.Is(err, errNoData) {
			return nil, noData("not in Shodan's scans")
		}
		return nil, err
	}
	r := &Result{Link: "https://www.shodan.io/host/" + ind.Value, Tags: resp.Tags}
	for _, t := range resp.Tags {
		if internetDBBad[t] {
			r.risk(75)
		}
	}
	ports := make([]string, len(resp.Ports))
	for i, p := range resp.Ports {
		ports[i] = strconv.Itoa(p)
	}
	r.Headline = fmt.Sprintf("%d open ports, %d known CVEs", len(ports), len(resp.Vulns))
	r.add("Open ports", firstN(ports, 20))
	r.add("Hostnames", firstN(resp.Hostnames, 5))
	r.add("Software", firstN(resp.CPEs, 5))
	r.add("CVEs", firstN(resp.Vulns, 10))
	return r, nil
}

// --- ProxyCheck --------------------------------------------------------------------------------

func lookupProxyCheck(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	q := url.Values{"vpn": {"1"}, "asn": {"1"}, "risk": {"1"}}
	if key != "" {
		q.Set("key", key)
	}
	var resp map[string]json.RawMessage
	if err := f.get(ctx, "https://proxycheck.io/v2/"+url.PathEscape(ind.Value)+"?"+q.Encode(), nil, &resp); err != nil {
		return nil, err
	}
	var status, message string
	_ = json.Unmarshal(resp["status"], &status)
	_ = json.Unmarshal(resp["message"], &message)
	if status == "denied" {
		return nil, fmt.Errorf("%w: %s", errQuota, message)
	}
	raw, ok := resp[ind.Value]
	if !ok {
		if status != "ok" {
			return nil, errors.New(trimText(message, 200))
		}
		return nil, errNoData
	}
	var d struct {
		Proxy    string `json:"proxy"`
		Type     string `json:"type"`
		Provider string `json:"provider"`
		Hostname string `json:"hostname"`
		Range    string `json:"range"`
		ASN      string `json:"asn"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, errors.New("proxycheck.io sent an unexpected answer")
	}
	r := &Result{Link: "https://proxycheck.io/threats/" + ind.Value}
	if d.Proxy == "yes" {
		r.Headline = "Anonymizing service: " + d.Type
		r.Tags = append(r.Tags, strings.ToLower(d.Type))
	} else {
		r.Headline = "Not a known proxy or VPN"
	}
	r.add("Proxy", d.Proxy)
	r.add("Type", d.Type)
	r.add("Provider", d.Provider)
	r.add("Hostname", d.Hostname)
	r.add("Range", d.Range)
	r.add("ASN", d.ASN)
	return r, nil
}

// --- urlscan.io --------------------------------------------------------------------------------

func lookupURLScan(ctx context.Context, f *fetcher, ind Indicator, key string) (*Result, error) {
	var q string
	switch ind.Kind {
	case KindIP:
		q = fmt.Sprintf("ip:%q", ind.Value)
	case KindDomain:
		q = "domain:" + ind.Value
	case KindURL:
		q = fmt.Sprintf("page.url:%q", ind.Value)
	}
	var resp struct {
		Total   int `json:"total"`
		Results []struct {
			ID   string `json:"_id"`
			Task struct {
				Time string `json:"time"`
			} `json:"task"`
			Page struct {
				IP        string `json:"ip"`
				ASN       string `json:"asn"`
				ASName    string `json:"asnname"`
				Country   string `json:"country"`
				Title     string `json:"title"`
				Server    string `json:"server"`
				TLSIssuer string `json:"tlsIssuer"`
				DomainAge *int   `json:"apexDomainAgeDays"`
			} `json:"page"`
		} `json:"results"`
	}
	u := "https://urlscan.io/api/v1/search/?size=1&q=" + url.QueryEscape(q)
	if err := f.get(ctx, u, map[string]string{"API-Key": key}, &resp); err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 {
		return nil, noData("no public scans")
	}
	s := resp.Results[0]
	r := &Result{Link: "https://urlscan.io/search/#" + url.PathEscape(q)}
	r.Headline = fmt.Sprintf("%d public scans, latest %s", resp.Total, dateOf(s.Task.Time))
	r.addInt("Public scans", resp.Total)
	r.add("Latest scan", dateOf(s.Task.Time))
	r.add("Page title", s.Page.Title)
	r.add("Server IP", s.Page.IP)
	r.add("Network", s.Page.ASName)
	r.add("Web server", s.Page.Server)
	r.add("TLS issuer", s.Page.TLSIssuer)
	if s.Page.DomainAge != nil && ind.Kind != KindIP {
		r.DomainAgeDays = s.Page.DomainAge
		r.addInt("Domain age (days)", *s.Page.DomainAge)
	}
	if s.ID != "" {
		r.add("Latest report", "https://urlscan.io/result/"+s.ID+"/")
	}
	return r, nil
}

// --- ipwho.is ----------------------------------------------------------------------------------

func lookupIPWho(ctx context.Context, f *fetcher, ind Indicator, _ string) (*Result, error) {
	var resp struct {
		Success     bool    `json:"success"`
		Message     string  `json:"message"`
		City        string  `json:"city"`
		Region      string  `json:"region"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		Lat         float64 `json:"latitude"`
		Lon         float64 `json:"longitude"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
		Timezone struct {
			ID string `json:"id"`
		} `json:"timezone"`
	}
	if err := f.get(ctx, "https://ipwho.is/"+url.PathEscape(ind.Value), nil, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		if strings.Contains(strings.ToLower(resp.Message), "limit") {
			return nil, fmt.Errorf("%w: %s", errQuota, resp.Message)
		}
		return nil, noData(trimText(resp.Message, 200))
	}
	g := &Geo{Lat: resp.Lat, Lon: resp.Lon, City: resp.City, Region: resp.Region, Country: resp.Country, CountryCode: resp.CountryCode,
		Org: resp.Connection.Org, ISP: resp.Connection.ISP, Timezone: resp.Timezone.ID}
	if resp.Connection.ASN != 0 {
		g.ASN = "AS" + strconv.Itoa(resp.Connection.ASN)
	}
	r := &Result{Geo: g}
	r.Headline = strings.Trim(strings.Join([]string{resp.City, resp.Country}, ", "), ", ")
	r.add("Location", strings.Trim(strings.Join([]string{resp.City, resp.Region, resp.Country}, ", "), ", "))
	r.add("ASN", g.ASN)
	r.add("Org", g.Org)
	r.add("ISP", g.ISP)
	r.add("Time zone", g.Timezone)
	return r, nil
}

// --- RDAP --------------------------------------------------------------------------------------

type rdapEntity struct {
	Roles    []string     `json:"roles"`
	Handle   string       `json:"handle"`
	VCard    []any        `json:"vcardArray"`
	Entities []rdapEntity `json:"entities"`
}

// vcardValue reads a property ("fn", "email", ...) from a jCard.
func (e rdapEntity) vcardValue(name string) string {
	if len(e.VCard) != 2 {
		return ""
	}
	props, _ := e.VCard[1].([]any)
	for _, p := range props {
		fields, _ := p.([]any)
		if len(fields) == 4 && fields[0] == name {
			if s, ok := fields[3].(string); ok {
				return s
			}
		}
	}
	return ""
}

func (e rdapEntity) hasRole(role string) bool {
	for _, r := range e.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// rdapFind returns the first value found for a role, searching nested entities.
func rdapFind(entities []rdapEntity, role, prop string) string {
	for _, e := range entities {
		if e.hasRole(role) {
			if v := e.vcardValue(prop); v != "" {
				return v
			}
		}
		if v := rdapFind(e.Entities, role, prop); v != "" {
			return v
		}
	}
	return ""
}

func lookupRDAP(ctx context.Context, f *fetcher, ind Indicator, _ string) (*Result, error) {
	var resp struct {
		Name      string       `json:"name"`
		Handle    string       `json:"handle"`
		Start     string       `json:"startAddress"`
		End       string       `json:"endAddress"`
		Country   string       `json:"country"`
		Type      string       `json:"type"`
		Status    []string     `json:"status"`
		Entities  []rdapEntity `json:"entities"`
		Nameserve []struct {
			Name string `json:"ldhName"`
		} `json:"nameservers"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	path := "domain/"
	if ind.Kind == KindIP {
		path = "ip/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/"+path+url.PathEscape(ind.Value), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	if err := f.do(req, nil, &resp); err != nil {
		if errors.Is(err, errNoData) {
			return nil, noData("no registration data")
		}
		return nil, err
	}
	w := &Whois{Registrant: rdapFind(resp.Entities, "registrant", "fn"), Registrar: rdapFind(resp.Entities, "registrar", "fn"), Abuse: rdapFind(resp.Entities, "abuse", "email")}
	var registered time.Time
	for _, e := range resp.Events {
		switch e.Action {
		case "registration":
			w.Created = dateOf(e.Date)
			registered, _ = time.Parse(time.RFC3339, e.Date)
		case "expiration":
			w.Expires = dateOf(e.Date)
		case "last changed":
			w.Updated = dateOf(e.Date)
		}
	}
	r := &Result{Whois: w}
	if ind.Kind == KindIP {
		w.NetName = resp.Name
		if resp.Start != "" {
			w.Range = resp.Start + " – " + resp.End
		}
		r.Headline = strings.TrimSpace(w.Registrant + " " + w.NetName)
		r.add("Registrant", w.Registrant)
		r.add("Net name", w.NetName)
		r.add("Range", w.Range)
		r.add("Country", resp.Country)
	} else {
		for _, ns := range resp.Nameserve {
			w.NameServer = append(w.NameServer, strings.ToLower(ns.Name))
		}
		r.Headline = "Registered " + w.Created
		if !registered.IsZero() {
			days := int(time.Since(registered).Hours() / 24)
			r.DomainAgeDays = &days
		}
		r.add("Registrar", w.Registrar)
		r.add("Registrant", w.Registrant)
		r.add("Name servers", firstN(w.NameServer, 4))
		r.add("Status", firstN(resp.Status, 4))
	}
	r.add("Created", w.Created)
	r.add("Updated", w.Updated)
	r.add("Expires", w.Expires)
	r.add("Abuse contact", w.Abuse)
	return r, nil
}
