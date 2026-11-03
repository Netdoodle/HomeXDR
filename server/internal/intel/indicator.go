// Package intel investigates indicators of compromise: it asks public threat intelligence
// services about an IP address, domain, URL or file hash, combines the answers into a score
// and a written brief, and finds where the indicator appears in this server's own events.
//
// A lookup sends the indicator to those services, so it only happens when someone (or the
// AI analyst) asks. Private addresses and internal names are never sent anywhere.
package intel

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Indicator kinds.
const (
	KindIP     = "ip"
	KindDomain = "domain"
	KindURL    = "url"
	KindHash   = "hash"
)

// Indicator is a parsed, normalized indicator.
type Indicator struct {
	Value    string `json:"value"`
	Kind     string `json:"kind"`
	HashType string `json:"hash_type,omitempty"` // md5 | sha1 | sha256
	// Private marks private addresses and internal names, which stay on this server.
	Private bool `json:"private"`
	// Host is a URL's host name or address.
	Host string `json:"-"`
}

// InputError is an indicator that could not be understood.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

const maxIndicator = 2048

var (
	hashRe   = regexp.MustCompile(`^[0-9a-f]+$`)
	domainRe = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$`)
	schemeRe = regexp.MustCompile(`(?i)^(?:hxxps?|https?|fxps?|ftps?)://`)
)

// defangReplacer undoes the ways analysts write indicators so they cannot be clicked.
var defangReplacer = strings.NewReplacer(
	"[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".", "[:]", ":", "[://]", "://", "[/]", "/",
)

// refang normalizes a pasted indicator: whitespace, quotes and defanging.
func refang(raw string) string {
	s := strings.Trim(strings.TrimSpace(raw), "\"'`<>")
	s = defangReplacer.Replace(s)
	if len(s) >= 4 && strings.EqualFold(s[:4], "hxxp") {
		s = "http" + s[4:]
	}
	if len(s) >= 4 && strings.EqualFold(s[:4], "fxp:") {
		s = "ftp:" + s[4:]
	}
	return s
}

// reservedPrefixes are special-use ranges that netip's own checks do not cover.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func privateAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return true
	}
	for _, p := range reservedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// internalSuffixes are top-level names that exist only inside a network.
var internalSuffixes = []string{"local", "lan", "home", "internal", "intranet", "corp", "localdomain", "localhost", "arpa", "test", "invalid", "example"}

func internalName(host string, extra []string) bool {
	if i := strings.LastIndexByte(host, '.'); i >= 0 && slices.Contains(internalSuffixes, host[i+1:]) {
		return true
	}
	for _, d := range extra {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Parse recognizes an IP address, domain, URL or MD5/SHA-1/SHA-256 hash. internal lists
// further domains (and their subdomains) that must stay on this server.
func Parse(raw string, internal []string) (Indicator, error) {
	s := refang(raw)
	bad := &InputError{"enter an IP address, domain, URL or file hash (MD5, SHA-1 or SHA-256)"}
	if s == "" {
		return Indicator{}, bad
	}
	if len(s) > maxIndicator {
		return Indicator{}, &InputError{fmt.Sprintf("the indicator is longer than %d characters", maxIndicator)}
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		a = a.Unmap().WithZone("")
		return Indicator{Value: a.String(), Kind: KindIP, Private: privateAddr(a)}, nil
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return Indicator{}, &InputError{"enter a single address, not a range"}
	}
	if h := strings.ToLower(s); hashRe.MatchString(h) {
		switch len(h) {
		case 32:
			return Indicator{Value: h, Kind: KindHash, HashType: "md5"}, nil
		case 40:
			return Indicator{Value: h, Kind: KindHash, HashType: "sha1"}, nil
		case 64:
			return Indicator{Value: h, Kind: KindHash, HashType: "sha256"}, nil
		}
		return Indicator{}, bad
	}
	if schemeRe.MatchString(s) || strings.ContainsAny(s, "/?") {
		return parseURL(s, internal)
	}
	d := strings.TrimSuffix(strings.ToLower(s), ".")
	if !domainRe.MatchString(d) || len(d) > 253 {
		return Indicator{}, bad
	}
	return Indicator{Value: d, Kind: KindDomain, Private: internalName(d, internal)}, nil
}

func parseURL(s string, internal []string) (Indicator, error) {
	bad := &InputError{"that does not look like a URL"}
	if !schemeRe.MatchString(s) {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return Indicator{}, bad
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	ind := Indicator{Kind: KindURL, Host: host}
	if a, err := netip.ParseAddr(host); err == nil {
		ind.Private = privateAddr(a)
	} else if domainRe.MatchString(host) {
		ind.Private = internalName(host, internal)
	} else {
		return Indicator{}, bad
	}
	u.Scheme, u.Host, u.Fragment = strings.ToLower(u.Scheme), strings.ToLower(u.Host), ""
	ind.Value = u.String()
	return ind, nil
}
