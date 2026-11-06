package behavior

import (
	"math"
	"strconv"
	"strings"
)

// Lists and limits below are starting points measured on one home network; see docs/behavior.md.

// benignClasses are services that are regular by design. Vendor-level public domains only;
// the owner adds more in settings.
var benignClasses = map[string][]string{
	"push notification": {"push.apple.com", "wns.windows.com", "notify.windows.com", "mtalk.google.com", "gcm.googleapis.com", "fcm.googleapis.com", "push.services.mozilla.com"},
	"endpoint security agent": {"cloudsink.net", "crowdstrike.com", "sentinelone.net", "endpoint.security.microsoft.com", "securitycenter.windows.com",
		"sophos.com", "sophosupd.com", "eset.com", "bitdefender.net", "tanium.com", "cybereason.net", "carbonblack.io"},
	"time sync":     {"ntp.org", "time.apple.com", "time.windows.com", "time.google.com", "time.cloudflare.com", "time.nist.gov"},
	"NAT traversal": {"stun.l.google.com", "stun.cloudflare.com", "tailscale.com"},
}

// housekeepingUDP are UDP ports whose traffic is regular by design: NTP, STUN, Tailscale.
func housekeepingUDP(port int) bool {
	switch port {
	case 123, 3478, 3479, 5349, 41641:
		return true
	}
	return port >= 19302 && port <= 19309
}

// pushTCP are the push notification ports of Apple and Google phones, for when the
// destination has no name.
func pushTCP(port int) bool { return port == 5223 || port == 5228 }

// discoveryPorts are local discovery protocols that talk to many hosts by design: DNS,
// DHCP, NTP, NetBIOS, SSDP, WS-Discovery, mDNS, LLMNR, UniFi discovery.
var discoveryPorts = []int{53, 67, 68, 123, 137, 138, 1900, 3702, 5353, 5355, 10001}

// localOnly reports names that only ever mean something inside the network.
func localOnly(name string) bool {
	for _, s := range []string{".arpa", ".local", ".localdomain", ".lan", ".home", ".internal", ".home.arpa"} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return !strings.Contains(name, ".")
}

// cdnDomains number their hosts, so their names look random. They apply when the offline
// popularity list is not loaded, and a tunnel needs a zone its owner controls anyway.
var cdnDomains = map[string]bool{
	"apple.com": true, "icloud.com": true, "apple-dns.net": true, "aaplimg.com": true, "akamai.net": true, "akamaiedge.net": true,
	"akadns.net": true, "akamaihd.net": true, "edgekey.net": true, "edgesuite.net": true, "cloudfront.net": true, "amazonaws.com": true,
	"google.com": true, "googleapis.com": true, "gstatic.com": true, "googlevideo.com": true, "googleusercontent.com": true,
	"1e100.net": true, "facebook.com": true, "fbcdn.net": true, "whatsapp.net": true, "microsoft.com": true, "windows.com": true,
	"windows.net": true, "azure.com": true, "azureedge.net": true, "msedge.net": true, "trafficmanager.net": true, "live.com": true,
	"office.com": true, "office365.com": true, "cloudflare.com": true, "cloudflare.net": true, "fastly.net": true, "netflix.com": true,
	"nflxso.net": true, "spotify.com": true, "sophosxl.net": true, "spamhaus.org": true, "ntp.org": true,
}

// multiPartSuffixes are the common public suffixes of two labels. The offline lists answer
// this properly when they are loaded; this is the fallback.
var multiPartSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "net.uk": true, "com.au": true, "net.au": true, "org.au": true,
	"co.nz": true, "org.nz": true, "co.jp": true, "ne.jp": true, "or.jp": true, "com.br": true, "com.cn": true, "net.cn": true, "co.in": true,
	"co.za": true, "co.kr": true, "com.mx": true, "com.tr": true, "com.tw": true, "com.sg": true, "com.hk": true, "co.il": true,
}

// baseDomain is a fallback for the registrable domain of a name.
func baseDomain(name string) string {
	labels := strings.Split(strings.Trim(name, "."), ".")
	if len(labels) <= 2 {
		return strings.Join(labels, ".")
	}
	n := len(labels)
	if multiPartSuffixes[labels[n-2]+"."+labels[n-1]] {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

func (rc *runCtx) registered(name string) string {
	if r := rc.enrich().Domain(name).Registered; r != "" {
		return r
	}
	return baseDomain(name)
}

// popular reports a domain on the offline popularity list, within the given rank.
func (rc *runCtx) popular(domain string, rank float64) bool {
	r := rc.enrich().Domain(domain).Rank
	return r > 0 && float64(r) <= rank
}

// suffixMatch reports a name equal to, or under, one of the domains.
func suffixMatch(name string, domains []string) bool {
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// benignClass names the service class a destination belongs to.
func benignClass(name string, extra []string) string {
	if name == "" {
		return ""
	}
	for class, domains := range benignClasses {
		if suffixMatch(name, domains) {
			return class
		}
	}
	if suffixMatch(name, extra) {
		return "listed in settings"
	}
	return ""
}

// entropy is a string's Shannon entropy in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	e := 0.0
	for _, n := range counts {
		p := float64(n) / float64(total)
		e -= p * math.Log2(p)
	}
	return e
}

// parsePortItem reads a port setting: "443", "tcp/443", "192.168.20.20:443" or
// "192.168.20.20:tcp/443". Empty parts mean any.
func parsePortItem(s string) (ip, proto string, port int, ok bool) {
	rest := s
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		ip, rest = rest[:i], rest[i+1:]
	}
	if p, n, found := strings.Cut(rest, "/"); found {
		proto, rest = strings.ToLower(p), n
		if proto != "tcp" && proto != "udp" {
			return "", "", 0, false
		}
	}
	port, err := strconv.Atoi(rest)
	if err != nil || port < 1 || port > 65535 {
		return "", "", 0, false
	}
	return ip, proto, port, true
}

// portListed reports whether a list of port settings covers this traffic.
func portListed(list []string, ip, proto string, port int) bool {
	for _, item := range list {
		i, pr, po, ok := parsePortItem(item)
		if ok && po == port && (pr == "" || pr == proto) && (i == "" || i == ip) {
			return true
		}
	}
	return false
}
