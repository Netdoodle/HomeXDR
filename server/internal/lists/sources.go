package lists

// The sources' URLs, formats and licence pages were checked from the owner's PC on 2026-11-05.
// docs/lists.md records what was found for each.

import (
	"strings"
	"time"
)

const (
	trancoFile = "top-1m.csv.zip"
	asnFile    = "ip2asn-combined.tsv.gz"
	ouiFile    = "oui.csv"
	manufFile  = "manuf"

	nrdDaysOnline = 5  // daily files the repository keeps at its root
	nrdKeepDays   = 30 // days of them kept here
	nrdSuffix     = "-free-newly-registered-domains.csv"
)

// ut1Categories come in precedence order: a domain on two lists keeps the first, so what
// matters to a security question comes before what only explains traffic away.
var ut1Categories = []struct{ id, label string }{
	{"malware", "malware"}, {"phishing", "phishing"}, {"cryptojacking", "cryptojacking"}, {"stalkerware", "stalkerware"},
	{"ddos", "ddos service"}, {"hacking", "hacking"}, {"dialer", "dialer"}, {"residential-proxies", "residential proxy"},
	{"doh", "DNS over HTTPS resolver"}, {"vpn", "VPN"}, {"remote-control", "remote control"}, {"warez", "warez"},
	{"download", "download site"}, {"filehosting", "file hosting"}, {"shortener", "URL shortener"}, {"publicite", "advertising"},
	{"marketingware", "marketing"}, {"chat", "chat"}, {"social_networks", "social network"}, {"webmail", "webmail"},
	{"audio-video", "audio and video"}, {"update", "software update"}, {"webhosting", "web hosting"},
}

func ut1File(cat string) string { return cat + ".tar.gz" }

// builtinSources are the lists this package answers lookups from.
func (s *Service) builtinSources() []*Source {
	return []*Source{
		{
			ID: "tranco", Name: "Tranco popular sites",
			About:   "Ranks the top million sites, so an alert can say whether a domain is well known.",
			SiteURL: "https://tranco-list.eu/", DefaultOn: true, Every: 7 * 24 * time.Hour, MaxBytes: 64 << 20, MinEntries: 100_000,
			License:    "No licence of its own. Free to use, with credit to the Tranco project. It is built from five lists, some of them for non-commercial use only (CC BY-NC 4.0).",
			LicenseURL: "https://tranco-list.eu/",
			Files: func(time.Time) []RemoteFile {
				return []RemoteFile{{Name: trancoFile, URL: "https://tranco-list.eu/top-1m.csv.zip"}}
			},
			Load: func(dir string) (func(), int, error) {
				t, err := loadTranco(dir)
				if err != nil {
					return nil, 0, err
				}
				return func() { s.tables.ranks.Store(t) }, t.size(), nil
			},
			Clear: func() { s.tables.ranks.Store(nil) },
		},
		{
			ID: "oui", Name: "MAC address vendors",
			About:   "Names the maker of a network card from the first half of its MAC address.",
			SiteURL: "https://standards-oui.ieee.org/", DefaultOn: true, Every: 30 * 24 * time.Hour, MaxBytes: 32 << 20, MinEntries: 10_000,
			License:    "IEEE's public registry listing, free to download. If IEEE refuses the download, Wireshark's copy of the same data is used instead.",
			LicenseURL: "https://standards.ieee.org/products-programs/regauth/",
			Files: func(time.Time) []RemoteFile {
				return []RemoteFile{{
					Name: ouiFile, URL: "https://standards-oui.ieee.org/oui/oui.csv",
					Fallback: &RemoteFile{Name: manufFile, URL: "https://www.wireshark.org/download/automated/data/manuf"},
				}}
			},
			Load: func(dir string) (func(), int, error) {
				t, err := loadOUI(dir)
				if err != nil {
					return nil, 0, err
				}
				return func() { s.tables.oui.Store(t) }, t.size(), nil
			},
			Clear: func() { s.tables.oui.Store(nil) },
		},
		{
			ID: "iptoasn", Name: "IP networks",
			About:   "Names the network and country behind an IP address.",
			SiteURL: "https://iptoasn.com/", DefaultOn: true, Every: 7 * 24 * time.Hour, MaxBytes: 64 << 20, MinEntries: 100_000,
			License: "Public domain (PDDL v1.0).", LicenseURL: "https://opendatacommons.org/licenses/pddl/1.0/",
			Files: func(time.Time) []RemoteFile {
				return []RemoteFile{{Name: asnFile, URL: "https://iptoasn.com/data/ip2asn-combined.tsv.gz"}}
			},
			Load: func(dir string) (func(), int, error) {
				t, err := loadASN(dir)
				if err != nil {
					return nil, 0, err
				}
				return func() { s.tables.asn.Store(t) }, t.entries(), nil
			},
			Clear: func() { s.tables.asn.Store(nil) },
		},
		{
			ID: "ut1", Name: "Website categories (UT1)",
			About:   "Sorts domains into categories such as advertising, VPN or file hosting.",
			SiteURL: "https://dsi.ut-capitole.fr/blacklists/", Every: 7 * 24 * time.Hour, MaxBytes: 64 << 20, MinEntries: 1000,
			Warning: "Its licence could not be read when this list was added, because the page was down. Check it yourself before turning this on.",
			License: "From Université Toulouse Capitole. Terms not confirmed: see their page.", LicenseURL: "https://dsi.ut-capitole.fr/blacklists/",
			Files: func(time.Time) []RemoteFile {
				out := make([]RemoteFile, 0, len(ut1Categories))
				for _, c := range ut1Categories {
					out = append(out, RemoteFile{Name: ut1File(c.id), URL: "https://dsi.ut-capitole.fr/blacklists/download/" + ut1File(c.id), Optional: true})
				}
				return out
			},
			Load: func(dir string) (func(), int, error) {
				t, err := loadCategories(dir)
				if err != nil {
					return nil, 0, err
				}
				return func() { s.tables.categories.Store(t) }, t.size(), nil
			},
			Clear: func() { s.tables.categories.Store(nil) },
		},
		{
			ID: "nrd", Name: "Newly registered domains",
			About:   "Flags domains registered in the last month. It is a sample of 10,000 a day, so a domain not on it may still be new.",
			SiteURL: "https://github.com/WhoisFreaks/daily-newly-registered-domains", Every: 24 * time.Hour, MaxBytes: 16 << 20, MinEntries: 1000,
			Warning: "The repository states no licence, so check that its terms suit you before turning this on.",
			License: "WhoisFreaks' free daily list. No licence stated.", LicenseURL: "https://github.com/WhoisFreaks/daily-newly-registered-domains",
			Files: func(now time.Time) []RemoteFile {
				out := make([]RemoteFile, 0, nrdDaysOnline)
				for i := 1; i <= nrdDaysOnline; i++ {
					name := now.AddDate(0, 0, -i).Format("2006-01-02") + nrdSuffix
					out = append(out, RemoteFile{Name: name, URL: "https://raw.githubusercontent.com/WhoisFreaks/daily-newly-registered-domains/main/" + name, Optional: true})
				}
				return out
			},
			KeepOld: func(name string, now time.Time) bool {
				day, ok := strings.CutSuffix(name, nrdSuffix)
				if !ok {
					return false
				}
				t, err := time.Parse("2006-01-02", day)
				return err == nil && now.Sub(t) <= nrdKeepDays*24*time.Hour
			},
			Load: func(dir string) (func(), int, error) {
				t, err := loadNewDomains(dir)
				if err != nil {
					return nil, 0, err
				}
				return func() { s.tables.newDomains.Store(t) }, t.size(), nil
			},
			Clear: func() { s.tables.newDomains.Store(nil) },
		},
	}
}
