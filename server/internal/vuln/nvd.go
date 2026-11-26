package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

// Some whole-OS products have no distro advisory feed, and CISA's catalog gives no version
// ranges, so a name match alone cannot say whether a host is affected. For these, the NVD's
// affected-version data (CPE ranges) is asked about the host's exact version. NVD's answer
// both confirms the CVEs that apply and drops catalog matches that do not.
const (
	nvdURL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdCacheFor = 24 * time.Hour
)

// nvdProducts maps a normalized OS name to its CPE "vendor:product".
var nvdProducts = map[string]string{
	"unraid":   "unraid:unraid",
	"unraidos": "unraid:unraid",
}

var cleanVersionRe = regexp.MustCompile(`^\d+(\.\d+){0,3}$`)

// nvdCVE is one CVE the NVD lists as affecting an exact product version.
type nvdCVE struct {
	ID      string
	Summary string
	CVSS    float64
	Vector  string
}

type nvdCacheEntry struct {
	at   time.Time
	cves []nvdCVE
}

// nvdProduct returns the CPE vendor:product for an OS package, and whether the NVD check
// applies to it.
func nvdProduct(p pkg) (string, bool) {
	if p.typ != "os" || !cleanVersionRe.MatchString(p.version) {
		return "", false
	}
	cpe, ok := nvdProducts[norm(p.name)]
	return cpe, ok
}

// nvdLookup returns the CVEs the NVD says affect that product version, cached for a day.
func (s *Service) nvdLookup(ctx context.Context, cpe, version string) ([]nvdCVE, error) {
	key := cpe + ":" + version
	s.nvdMu.Lock()
	if e, ok := s.nvdCache[key]; ok && s.now().Sub(e.at) < nvdCacheFor {
		s.nvdMu.Unlock()
		return e.cves, nil
	}
	s.nvdMu.Unlock()

	q := url.Values{}
	q.Set("cpeName", "cpe:2.3:o:"+cpe+":"+version+":*:*:*:*:*:*:*")
	q.Set("resultsPerPage", "2000")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.NVDURL+"?"+q.Encode()+"&isVulnerable", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, errors.New("could not reach services.nvd.nist.gov. If your firewall or DNS blocklist blocks it, allow this host or turn this check off")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("services.nvd.nist.gov answered HTTP %d", resp.StatusCode)
	}
	var res struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&res); err != nil {
		return nil, fmt.Errorf("services.nvd.nist.gov sent something unreadable: %w", err)
	}
	out := []nvdCVE{}
	for _, v := range res.Vulnerabilities {
		c := nvdCVE{ID: v.CVE.ID}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				c.Summary = d.Value
				break
			}
		}
		// Newest CVSS version first.
		for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30"} {
			if ms := v.CVE.Metrics[k]; len(ms) > 0 {
				c.CVSS, c.Vector = ms[0].CVSSData.BaseScore, ms[0].CVSSData.VectorString
				break
			}
		}
		if cveRe.MatchString(c.ID) {
			out = append(out, c)
		}
	}
	s.nvdMu.Lock()
	if s.nvdCache == nil {
		s.nvdCache = map[string]nvdCacheEntry{}
	}
	s.nvdCache[key] = nvdCacheEntry{at: s.now(), cves: out}
	s.nvdMu.Unlock()
	return out, nil
}

// nvdRefine settles the catalog matches for whole-OS products with the NVD's version data. A
// match the NVD does not list for the host's version is dropped, one it lists is confirmed,
// and CVEs the NVD lists that the catalog does not are added. If the NVD cannot be reached,
// the matches stay as they were.
func (s *Service) nvdRefine(ctx context.Context, host *store.Host, matches []store.VulnMatch, pkgs []pkg) ([]store.VulnMatch, []store.VulnFinding, error) {
	var extra []store.VulnFinding
	for _, p := range pkgs {
		cpe, ok := nvdProduct(p)
		if !ok {
			continue
		}
		cves, err := s.nvdLookup(ctx, cpe, p.version)
		if err != nil {
			return matches, extra, err
		}
		listed := map[string]nvdCVE{}
		for _, c := range cves {
			listed[c.ID] = c
		}
		kept := matches[:0:0]
		seen := map[string]bool{}
		for _, m := range matches {
			if m.PackageType != "os" || norm(m.Package) != norm(p.name) {
				kept = append(kept, m)
				continue
			}
			c, ok := listed[m.CVE]
			if !ok {
				continue // the NVD does not list this version as affected
			}
			seen[m.CVE] = true
			m.Confidence = Confirmed
			m.Reason = fmt.Sprintf("The NVD lists version %s of %s as affected by %s.", p.version, p.name, c.ID)
			kept = append(kept, m)
		}
		matches = kept
		for _, c := range cves {
			if seen[c.ID] {
				continue
			}
			cv := c.CVSS
			f := store.VulnFinding{
				HostID: host.ID, Hostname: host.Hostname, Package: p.name, SourcePackage: p.name, Version: p.version, PackageType: p.typ,
				CVE: c.ID, Title: shortTitle(c.Summary, c.ID), Summary: c.Summary, Confidence: Confirmed,
				SeveritySource: "nvd", CVSSVector: c.Vector,
			}
			if c.CVSS > 0 {
				f.CVSS = &cv
			} else {
				est := 7.5
				f.CVSS, f.SeveritySource = &est, "estimated"
			}
			if info, ok := parseCVSS(c.Vector); ok {
				f.AttackVector = info.AttackVector
			}
			extra = append(extra, f)
		}
	}
	return matches, extra, nil
}
