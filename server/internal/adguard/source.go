package adguard

import (
	"context"
	"time"
)

// Resolver kinds, stored in Settings.Kind. An empty kind is AdGuard Home, so settings saved
// before other resolvers existed keep working.
const (
	KindAdGuard    = "adguard"
	KindPiHole     = "pihole"
	KindTechnitium = "technitium"

	productAdGuard    = "AdGuard Home"
	productPiHole     = "Pi-hole"
	productTechnitium = "Technitium DNS Server"
)

// source is one resolver's query log, read newest first in pages.
type source interface {
	// Status checks the connection and the login, and returns the resolver's version.
	Status(ctx context.Context) (*Status, error)
	// QueryLog returns up to limit entries, newest first, starting after the page token
	// (empty: the newest). The page's Oldest is the token of the next, older page; empty
	// when there is none.
	QueryLog(ctx context.Context, token string, limit int) (*Page, error)
	// StartBefore is a page token for entries logged before t, so the history import
	// starts where live importing began. Sources that cannot seek return "" and the
	// history import skips the newer entries itself.
	StartBefore(t time.Time) string
	// Close ends any login session the source opened.
	Close(ctx context.Context)
}

// normalKind maps a stored kind to one of the Kind constants.
func normalKind(k string) string {
	switch k {
	case KindPiHole, KindTechnitium:
		return k
	}
	return KindAdGuard
}

// Product is the resolver's name, for messages.
func Product(kind string) string {
	switch normalKind(kind) {
	case KindPiHole:
		return productPiHole
	case KindTechnitium:
		return productTechnitium
	}
	return productAdGuard
}

// DatasetFor is event.dataset of a resolver's lookups.
func DatasetFor(kind string) string {
	switch normalKind(kind) {
	case KindPiHole:
		return DatasetPiHole
	case KindTechnitium:
		return DatasetTechnitium
	}
	return Dataset
}

// needsUsername reports whether the resolver's login has a username. Pi-hole uses a
// password only and Technitium an API token.
func needsUsername(kind string) bool { return normalKind(kind) == KindAdGuard }

// newSource returns the query log reader for the settings' resolver.
func newSource(set Settings) (source, error) {
	switch normalKind(set.Kind) {
	case KindPiHole:
		return newPiHole(set)
	case KindTechnitium:
		return newTechnitium(set)
	}
	return NewClient(set)
}

// StartBefore is AdGuard Home's older_than: entries strictly before t.
func (c *Client) StartBefore(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// Close does nothing: AdGuard Home's API uses basic auth, without sessions.
func (c *Client) Close(context.Context) {}
