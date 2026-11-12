package av

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Yara talks to the homexdr-yara scanner (internal/yarasvc) over HTTP.
type Yara struct {
	URL  string // e.g. http://yara:3320
	HTTP *http.Client
}

// NewYara accepts "host:port" or a URL.
func NewYara(addr string) *Yara {
	u := strings.TrimRight(strings.TrimSpace(addr), "/")
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	return &Yara{URL: u, HTTP: &http.Client{Timeout: 3 * time.Minute}}
}

// YaraMatch is one rule that matched.
type YaraMatch struct {
	Namespace string `json:"namespace"`
	Rule      string `json:"rule"`
}

// YaraStatus describes the scanner, for the settings page.
type YaraStatus struct {
	Configured  bool       `json:"configured"`
	OK          bool       `json:"ok"`
	YaraVersion string     `json:"yara_version,omitempty"`
	Rules       int        `json:"rules"`
	Package     string     `json:"package,omitempty"`
	CustomFiles int        `json:"custom_files"`
	Compiled    *time.Time `json:"compiled,omitempty"`
	Error       string     `json:"error,omitempty"`
	CustomError string     `json:"custom_error,omitempty"`
}

func (y *Yara) do(req *http.Request, out any) error {
	resp, err := y.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return fmt.Errorf("yara scanner: %s", e.Error)
		}
		return fmt.Errorf("yara scanner: HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// Scan sends the file and returns the rules that matched.
func (y *Yara) Scan(ctx context.Context, r io.Reader) ([]YaraMatch, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, y.URL+"/scan", r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	var res struct {
		Matches []YaraMatch `json:"matches"`
	}
	if err := y.do(req, &res); err != nil {
		return nil, err
	}
	return res.Matches, nil
}

// Status asks the scanner how it is.
func (y *Yara) Status(ctx context.Context) (YaraStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, y.URL+"/status", nil)
	if err != nil {
		return YaraStatus{}, err
	}
	var st YaraStatus
	if err := y.do(req, &st); err != nil {
		return st, err
	}
	st.Configured = true
	return st, nil
}

// Verdict sources for YARA. Rules for hacking tools and generic suspicious traits match
// programs people use on purpose (admin and pentest tools, packed installers), so they
// raise an alert without the automatic stop and quarantine.
const (
	SourceYara           = "yara"
	SourceYaraTool       = "yara:tool"
	SourceYaraSuspicious = "yara:suspicious"
)

var (
	yaraToolRe       = regexp.MustCompile(`(?i)(hktl|hacktool|_pua_|^pua_|_tool_|_tools_|offensive|redteam|_pentest)`)
	yaraSuspiciousRe = regexp.MustCompile(`(?i)(indicator_|suspicious|_susp_|^susp_|_packed|_generic|anomal)`)
)

// YaraClass sorts a rule into malware, tool or suspicious by its name.
func YaraClass(rule string) string {
	switch {
	case yaraToolRe.MatchString(rule):
		return SourceYaraTool
	case yaraSuspiciousRe.MatchString(rule):
		return SourceYaraSuspicious
	}
	return SourceYara
}

// AlertOnly reports whether a verdict source never triggers the automatic response.
func AlertOnly(source string) bool {
	return source == SourceYaraTool || source == SourceYaraSuspicious
}

// yaraVerdict picks the most serious match: malware over tool over suspicious.
func yaraVerdict(ms []YaraMatch) (source, sig string) {
	rank := map[string]int{SourceYara: 0, SourceYaraTool: 1, SourceYaraSuspicious: 2}
	best := -1
	for i, m := range ms {
		if best < 0 || rank[YaraClass(m.Rule)] < rank[YaraClass(ms[best].Rule)] {
			best = i
		}
	}
	source, sig = YaraClass(ms[best].Rule), ms[best].Rule
	if len(ms) > 1 {
		sig += fmt.Sprintf(" (+%d more)", len(ms)-1)
	}
	return source, sig
}
