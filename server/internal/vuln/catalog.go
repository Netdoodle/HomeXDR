package vuln

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Entry is one vulnerability on CISA's catalog.
type Entry struct {
	CVE         string `json:"cveID"`
	Vendor      string `json:"vendorProject"`
	Product     string `json:"product"`
	Name        string `json:"vulnerabilityName"`
	DateAdded   string `json:"dateAdded"`
	Description string `json:"shortDescription"`
	DueDate     string `json:"dueDate"`
	Ransomware  string `json:"knownRansomwareCampaignUse"`
}

// catalog indexes entries by the package names they match.
type catalog struct {
	version string
	entries int
	byName  map[string][]*Entry
}

type kevFile struct {
	Title           string  `json:"title"`
	CatalogVersion  string  `json:"catalogVersion"`
	Vulnerabilities []Entry `json:"vulnerabilities"`
}

// parseCatalog reads the KEV JSON file.
func parseCatalog(path string) (*catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f kevFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("not the catalog's JSON: %w", err)
	}
	c := &catalog{version: f.CatalogVersion, entries: len(f.Vulnerabilities), byName: map[string][]*Entry{}}
	for i := range f.Vulnerabilities {
		e := &f.Vulnerabilities[i]
		for _, name := range packageNames(e.Vendor, e.Product) {
			c.byName[name] = append(c.byName[name], e)
		}
	}
	return c, nil
}

// norm reduces a name to lower-case letters and digits, so OpenSSL, open-ssl and open_ssl compare equal.
func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// aliases says which package names a catalog entry goes by, keyed by normalized "vendor|product".
// A product name alone is not enough: "Core" (WordPress and Drupal), "Frontend" (Zabbix) or
// "Kernel" (Linux) would match whatever happens to share the word. So a name matches only when
// vendor and product are the same (Sudo/Sudo), or through this table.
var aliases = map[string][]string{
	"apache|httpserver":                           {"apache2", "httpd", "apache"},
	"apache|log4j2":                               {"log4j", "log4j2", "liblog4j2java"},
	"apache|tomcat":                               {"tomcat", "tomcat9", "tomcat10", "tomcat11"},
	"apache|activemq":                             {"activemq"},
	"apache|solr":                                 {"solr"},
	"artifex|ghostscript":                         {"ghostscript"},
	"atlassian|confluence":                        {"confluence"},
	"drupal|core":                                 {"drupal"},
	"drupal|drupalcore":                           {"drupal"},
	"elastic|elasticsearch":                       {"elasticsearch"},
	"elastic|kibana":                              {"kibana"},
	"exim|exim":                                   {"exim", "exim4"},
	"exim|eximinternetmailer":                     {"exim", "exim4"},
	"exim|mailtransferagentmta":                   {"exim", "exim4"},
	"gitlab|communityandenterpriseeditions":       {"gitlab", "gitlabce", "gitlabee"},
	"gitlab|communityeditionandenterpriseedition": {"gitlab", "gitlabce", "gitlabee"},
	"gitlab|gitlab":                               {"gitlab", "gitlabce", "gitlabee"},
	"gitlab|gitlabceee":                           {"gitlab", "gitlabce", "gitlabee"},
	"gnu|bourneagainshellbash":                    {"bash"},
	"gnu|gnubash":                                 {"bash"},
	"gnu|gnuclibrary":                             {"glibc", "libc6", "glibcsolibs", "aaaglibcsolibs"},
	"gnu|inetutils":                               {"inetutils"},
	"google|chromium":                             {"chromium"},
	"grafanalabs|grafana":                         {"grafana"},
	"isc|bind":                                    {"bind", "bind9", "named"},
	"jetbrains|teamcity":                          {"teamcity", "teamcityserver"},
	"linux|kernel":                                {"kernel", "linux", "linuximage", "kernelhuge", "kernelgeneric"},
	"mongodb|mongodbandmongodbserver":             {"mongodb", "mongod", "mongo", "mongodbserver"},
	"mongodb|mongoexpress":                        {"mongoexpress"},
	"mozilla|firefox":                             {"firefox", "firefoxesr"},
	"mozilla|firefoxandthunderbird":               {"firefox", "firefoxesr", "thunderbird"},
	"mozilla|firefoxfirefoxesrandthunderbird":     {"firefox", "firefoxesr", "thunderbird"},
	"nagios|nagiosxi":                             {"nagiosxi"},
	"openssl|openssl":                             {"openssl", "opensslsolibs", "libssl3", "libssl3t64", "libssl11"},
	"php|fastcgiprocessmanagerfpm":                {"phpfpm", "php"},
	"php|php":                                     {"php", "phpfpm", "libapache2modphp"},
	"phpgroup|php":                                {"php", "phpfpm", "libapache2modphp"},
	"plex|mediaserver":                            {"plex", "plexmediaserver", "pms", "pmsdocker"},
	"redhat|polkit":                               {"polkit", "policykit1"},
	"roundcube|roundcubewebmail":                  {"roundcube", "roundcubemail"},
	"roundcube|webmail":                           {"roundcube", "roundcubemail"},
	"samba|samba":                                 {"samba", "sambacommon"},
	"sonatype|nexusrepository":                    {"nexus", "nexus3"},
	"sonatype|nexusrepositorymanager":             {"nexus", "nexus3"},
	"unraid|unraid":                               {"unraid", "unraidos"},
	"wordpress|core":                              {"wordpress"},
	"wordpress|wordpresscore":                     {"wordpress"},
	"zabbix|frontend":                             {"zabbixfrontendphp"},
}

// packageNames returns the normalized package names a catalog entry applies to.
func packageNames(vendor, product string) []string {
	v, p := norm(vendor), norm(product)
	if a, ok := aliases[v+"|"+p]; ok {
		return a
	}
	if v == p && len(p) >= 3 {
		return []string{p}
	}
	return nil
}

// imageName reduces a Docker image to the name people call it: lscr.io/linuxserver/plex is plex.
func imageName(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

var (
	versionBoundRe = regexp.MustCompile(`(?i)\b(before|prior to|earlier than|through|up to and including)\s+(?:versions?\s+|v)?(\d+(?:\.\d+)+[a-z0-9.\-]*)`)
	versionRangeRe = regexp.MustCompile(`(?i)\b(?:between|from)\s+(?:versions?\s+|v)?\d|\d\s+(?:through|to)\s+(?:versions?\s+|v)?\d`)
)

// bound is an upper limit on affected versions, read from the catalog's description.
type bound struct {
	version   string
	inclusive bool // "through" rather than "before"
}

// descriptionBound finds the one version limit a description states. Several different ones,
// or a range with a lower end, are not safe to read this way, so they give nothing.
func descriptionBound(text string) (bound, bool) {
	if versionRangeRe.MatchString(text) {
		return bound{}, false
	}
	var found bound
	ok := false
	for _, m := range versionBoundRe.FindAllStringSubmatch(text, -1) {
		v := strings.TrimRight(m[2], ".-")
		b := bound{v, strings.EqualFold(m[1], "through") || strings.EqualFold(m[1], "up to and including")}
		if ok && b != found {
			return bound{}, false
		}
		found, ok = b, true
	}
	return found, ok
}

type verPart struct {
	num   int64
	text  string
	isNum bool
}

// splitVersion breaks 1.9.17p2 into 1, 9, 17, p, 2. It fails on versions not starting with a number.
func splitVersion(v string) ([]verPart, bool) {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	if v == "" || v[0] < '0' || v[0] > '9' {
		return nil, false
	}
	var out []verPart
	for i := 0; i < len(v); {
		c := v[i]
		j := i
		switch {
		case c >= '0' && c <= '9':
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			n, err := strconv.ParseInt(v[i:j], 10, 64)
			if err != nil {
				return nil, false
			}
			out = append(out, verPart{num: n, isNum: true})
		case c >= 'a' && c <= 'z':
			for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
				j++
			}
			out = append(out, verPart{text: v[i:j]})
		default:
			j = i + 1
		}
		i = j
	}
	return out, true
}

func preRelease(s string) bool {
	switch s {
	case "alpha", "beta", "rc", "pre", "dev", "a", "b":
		return true
	}
	return false
}

// compareVersions orders two versions the way upstream projects number them. ok is false when
// either cannot be read as a version.
func compareVersions(a, b string) (cmp int, ok bool) {
	pa, oka := splitVersion(a)
	pb, okb := splitVersion(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y verPart
		x.isNum, y.isNum = true, true
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		switch {
		case x.isNum && y.isNum:
			if x.num != y.num {
				if x.num < y.num {
					return -1, true
				}
				return 1, true
			}
		case !x.isNum && !y.isNum:
			if x.text != y.text {
				if preRelease(x.text) != preRelease(y.text) {
					if preRelease(x.text) {
						return -1, true
					}
					return 1, true
				}
				return strings.Compare(x.text, y.text), true
			}
		case x.isNum: // 1.2 against 1.2a or 1.2rc
			if preRelease(y.text) {
				return 1, true
			}
			return -1, true
		default:
			if preRelease(x.text) {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// trustsVersionNumber reports whether a package's version number can settle a check. Debian,
// Red Hat and Alpine fix old versions without raising the number, so it cannot for them.
func trustsVersionNumber(pkgType, version string) bool {
	switch pkgType {
	case "slackware", "pacman", "os":
		return true
	case "docker":
		// A tag is a version only when it names a full one: 1.27 floats to the newest 1.27.x.
		v, _, _ := strings.Cut(strings.TrimPrefix(version, "v"), "-")
		parts := strings.Split(v, ".")
		return len(parts) >= 3
	}
	return false
}

// comparableVersion drops a distribution suffix from an image tag: 1.27.3-alpine is 1.27.3.
func comparableVersion(pkgType, version string) string {
	if pkgType == "docker" {
		v, _, _ := strings.Cut(version, "-")
		return v
	}
	return version
}
