package core

import (
	"time"

	"github.com/Netdoodle/homexdr/server/internal/adguard"
)

// Pulled source states.
const (
	PulledOnline  = "online"
	PulledOffline = "offline"
	PulledWaiting = "waiting"
)

// PulledSource is a source HomeXDR reads from on a timer rather than one that sends to it,
// such as a DNS resolver's query log. It is not a host: its data is filed under the host it
// runs on, and its status is whether the last read worked.
type PulledSource struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Dataset string `json:"dataset"`
	Status  string `json:"status"`
	// Explanation says what the status means, and the last error when offline.
	Explanation string     `json:"explanation,omitempty"`
	LastPoll    *time.Time `json:"last_poll,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	IntervalSec int        `json:"interval_sec"`
	// SettingsPath is the console page where the source is set up.
	SettingsPath string `json:"settings_path"`
}

// pulledSources lists the sources HomeXDR reads from. A source that is turned off is left out.
func (c *Core) pulledSources() []PulledSource {
	out := []PulledSource{}
	if c == nil || c.AdGuard == nil {
		return out
	}
	v := c.AdGuard.View()
	if !v.Enabled {
		return out
	}
	p := PulledSource{
		ID: "dns_query_log", Name: adguard.Product(v.Kind) + " query log", Address: v.URL, Dataset: adguard.DatasetFor(v.Kind),
		LastPoll: v.Status.LastPoll, LastSuccess: v.Status.LastSuccess, IntervalSec: v.IntervalSec, SettingsPath: "/settings/network",
	}
	switch v.Status.State {
	case "ok":
		p.Status, p.Explanation = PulledOnline, "The last read of the query log worked."
	case "error":
		p.Status = PulledOffline
		p.Explanation = "The last read failed: " + v.Status.LastError
	default:
		p.Status, p.Explanation = PulledWaiting, "Not read yet since the server started."
	}
	return append(out, p)
}
