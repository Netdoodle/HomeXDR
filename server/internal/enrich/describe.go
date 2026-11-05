package enrich

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// Facts is what the offline lists say about one indicator. Only the part that fits the
// indicator's kind is set.
type Facts struct {
	Domain *DomainInfo `json:"domain,omitempty"`
	IP     *IPInfo     `json:"ip,omitempty"`
	MAC    *MACInfo    `json:"mac,omitempty"`
}

var (
	macRe    = regexp.MustCompile(`(?i)^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$|^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$`)
	domainRe = regexp.MustCompile(`(?i)^[a-z0-9_]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9])?)+\.?$`)
)

// Describe looks up an IP address, domain, URL or MAC address. It returns nil for anything
// else, such as a file hash, and when the lists know nothing about it.
func Describe(l Lookup, value string) *Facts {
	v := strings.TrimSpace(value)
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return nil
		}
		v = u.Hostname()
	}
	switch {
	case v == "":
		return nil
	case macRe.MatchString(v):
		if m := l.MAC(v); m != (MACInfo{}) {
			return &Facts{MAC: &m}
		}
		return nil
	}
	if _, err := netip.ParseAddr(v); err == nil {
		if i := l.IP(v); i != (IPInfo{}) {
			return &Facts{IP: &i}
		}
		return nil
	}
	if domainRe.MatchString(v) {
		if d := l.Domain(v); d != (DomainInfo{}) {
			return &Facts{Domain: &d}
		}
	}
	return nil
}
