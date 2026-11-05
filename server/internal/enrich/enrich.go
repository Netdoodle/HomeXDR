// Package enrich answers offline questions about domains, IP addresses and MAC addresses
// from lists downloaded in advance, so no query about the network ever leaves it.
package enrich

// DomainInfo is what the offline lists know about a domain. Zero values mean unknown.
type DomainInfo struct {
	// Registered is the registrable domain (example.co.uk for a.b.example.co.uk).
	Registered string `json:"registered,omitempty"`
	// Rank is the domain's popularity rank; 0 means it is not on the popularity list.
	Rank int `json:"rank,omitempty"`
	// Category is a content category such as "news" or "malware".
	Category string `json:"category,omitempty"`
	// NewlyRegistered reports that the domain is on a newly registered domains list.
	NewlyRegistered bool `json:"newly_registered,omitempty"`
}

// IPInfo is what the offline lists know about an IP address.
type IPInfo struct {
	ASN     int    `json:"asn,omitempty"`
	ASName  string `json:"as_name,omitempty"`
	Country string `json:"country,omitempty"`
}

// MACInfo is what the offline lists know about a MAC address.
type MACInfo struct {
	Vendor string `json:"vendor,omitempty"`
	// Randomized reports a locally administered address, as phones use for privacy.
	Randomized bool `json:"randomized,omitempty"`
}

// Lookup is implemented by the offline list service. Lookups never touch the network and
// are cheap enough to call while handling events.
type Lookup interface {
	Domain(name string) DomainInfo
	IP(ip string) IPInfo
	MAC(mac string) MACInfo
}

// Nop knows nothing. It is used until the lists are loaded.
type Nop struct{}

func (Nop) Domain(string) DomainInfo { return DomainInfo{} }
func (Nop) IP(string) IPInfo         { return IPInfo{} }
func (Nop) MAC(string) MACInfo       { return MACInfo{} }
