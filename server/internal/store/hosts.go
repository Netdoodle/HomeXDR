package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Host kinds.
const (
	HostEndpoint = "endpoint"
	HostNetwork  = "network"
)

// Online windows: an endpoint is online if it heartbeated recently; a network device if
// it sent a log recently.
const (
	EndpointOnlineWindow = 2 * time.Minute
	NetworkOnlineWindow  = 15 * time.Minute
)

// Host is a host record in API shape.
type Host struct {
	ID             string             `json:"id"`
	Hostname       string             `json:"hostname"`
	Kind           string             `json:"kind"`
	OS             event.OS           `json:"os"`
	Arch           string             `json:"arch,omitempty"`
	IPs            []string           `json:"ips"`
	MACs           []string           `json:"macs,omitempty"`
	AgentVersion   string             `json:"agent_version,omitempty"`
	Status         string             `json:"status"`
	Isolated       bool               `json:"isolated"`
	LastSeen       *time.Time         `json:"last_seen,omitempty"`
	EnrolledAt     time.Time          `json:"enrolled_at"`
	Labels         []string           `json:"labels"`
	Sensors        []api.SensorStatus `json:"sensors,omitempty"`
	QueueEvents    int64              `json:"queue_events,omitempty"`
	AllowedActions []string           `json:"allowed_actions,omitempty"`
	OpenAlerts     int                `json:"open_alerts"`
	BootTime       *time.Time         `json:"boot_time,omitempty"`
	CPUs           int                `json:"cpus,omitempty"`
	MemoryBytes    uint64             `json:"memory_bytes,omitempty"`

	Revoked    bool   `json:"-"`
	CertSerial string `json:"-"`
	SourceIP   string `json:"-"`
	ConfigVer  int64  `json:"-"`
}

const hostCols = `h.id, h.kind, h.hostname, h.info, h.status, h.labels, h.enrolled_at, h.last_seen,
	h.revoked, h.isolated, h.cert_serial, h.source_ip,
	(SELECT COUNT(*) FROM alerts a WHERE a.host_id = h.id AND a.status IN ('new','in_progress'))`

func scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	var h Host
	var info, status, labels, enrolled string
	var last sql.NullString
	var revoked, isolated int
	if err := row.Scan(&h.ID, &h.Kind, &h.Hostname, &info, &status, &labels, &enrolled, &last,
		&revoked, &isolated, &h.CertSerial, &h.SourceIP, &h.OpenAlerts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var hi api.HostInfo
	var st api.AgentStatus
	unmarshalJSON(info, &hi)
	unmarshalJSON(status, &st)
	unmarshalJSON(labels, &h.Labels)
	if h.Labels == nil {
		h.Labels = []string{}
	}
	h.OS = hi.OS
	h.Arch = hi.Arch
	h.IPs = hi.IPs
	if h.IPs == nil {
		h.IPs = []string{}
	}
	h.MACs = hi.MACs
	h.BootTime = hi.BootTime
	h.CPUs = hi.CPUs
	h.MemoryBytes = hi.MemoryBytes
	h.AgentVersion = st.Version
	h.Sensors = st.Sensors
	h.QueueEvents = st.QueueEvents
	h.AllowedActions = st.AllowedActions
	h.ConfigVer = st.ConfigVersion
	h.EnrolledAt = parseTS(enrolled)
	h.LastSeen = parseNullTS(last)
	h.Revoked = revoked != 0
	h.Isolated = isolated != 0
	h.Status = hostStatus(&h)
	return &h, nil
}

func hostStatus(h *Host) string {
	switch {
	case h.Revoked:
		return "revoked"
	case h.Isolated:
		return "isolated"
	}
	window := EndpointOnlineWindow
	if h.Kind == HostNetwork {
		window = NetworkOnlineWindow
	}
	if h.LastSeen != nil && time.Since(*h.LastSeen) < window {
		return "online"
	}
	return "offline"
}

// CreateEndpoint registers a newly enrolled agent.
func (s *Store) CreateEndpoint(ctx context.Context, id string, info api.HostInfo, labels []string, certSerial string) (*Host, error) {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO hosts(id, kind, hostname, platform, info, labels, enrolled_at, last_seen, cert_serial)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		id, HostEndpoint, info.Hostname, info.OS.Platform, mustJSON(info), mustJSON(cleanLabels(labels)), ts(now), ts(now), certSerial)
	if err != nil {
		return nil, err
	}
	return s.GetHost(ctx, id)
}

// GetHost returns a host by ID.
func (s *Store) GetHost(ctx context.Context, id string) (*Host, error) {
	return scanHost(s.db.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts h WHERE h.id = ?`, id))
}

// HostFilter selects hosts.
type HostFilter struct {
	Q        string // hostname or IP substring
	Status   string
	Label    string
	Platform string
	Kind     string
	IDs      []string
	Labels   []string // any of
}

// ListHosts returns hosts matching f, ordered by hostname.
func (s *Store) ListHosts(ctx context.Context, f HostFilter) ([]*Host, error) {
	q := `SELECT ` + hostCols + ` FROM hosts h WHERE 1=1`
	var args []any
	if f.Q != "" {
		q += ` AND (h.hostname LIKE ? ESCAPE '\' OR h.info LIKE ? ESCAPE '\')`
		like := "%" + escapeLike(f.Q) + "%"
		args = append(args, like, like)
	}
	if f.Platform != "" {
		q += ` AND h.platform = ?`
		args = append(args, f.Platform)
	}
	if f.Kind != "" {
		q += ` AND h.kind = ?`
		args = append(args, f.Kind)
	}
	if len(f.IDs) > 0 {
		q += ` AND h.id IN (` + placeholders(len(f.IDs)) + `)`
		for _, id := range f.IDs {
			args = append(args, id)
		}
	}
	q += ` ORDER BY h.hostname COLLATE NOCASE`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		if f.Status != "" && h.Status != f.Status {
			continue
		}
		if f.Label != "" && !containsFold(h.Labels, f.Label) {
			continue
		}
		if len(f.Labels) > 0 && !anyFold(h.Labels, f.Labels) {
			continue
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Heartbeat records host info and agent status, and returns the updated host.
func (s *Store) Heartbeat(ctx context.Context, id string, info api.HostInfo, st api.AgentStatus) (*Host, error) {
	_, err := s.db.ExecContext(ctx,
		`UPDATE hosts SET hostname = ?, platform = ?, info = ?, status = ?, last_seen = ? WHERE id = ?`,
		info.Hostname, info.OS.Platform, mustJSON(info), mustJSON(st), ts(time.Now()), id)
	if err != nil {
		return nil, err
	}
	return s.GetHost(ctx, id)
}

// TouchHost updates last_seen.
func (s *Store) TouchHost(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET last_seen = ? WHERE id = ?`, ts(time.Now()), id)
	return err
}

// cleanLabels trims labels and drops empty, overlong and case-insensitive duplicates.
func cleanLabels(labels []string) []string {
	clean := []string{}
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if l != "" && len(l) <= 64 && !containsFold(clean, l) {
			clean = append(clean, l)
		}
	}
	return clean
}

// SetLabels replaces a host's labels.
func (s *Store) SetLabels(ctx context.Context, id string, labels []string) (*Host, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE hosts SET labels = ? WHERE id = ?`, mustJSON(cleanLabels(labels)), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return s.GetHost(ctx, id)
}

// SetIsolated records whether a host is network-isolated.
func (s *Store) SetIsolated(ctx context.Context, id string, isolated bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET isolated = ? WHERE id = ?`, boolInt(isolated), id)
	return err
}

// RevokeHost marks a host revoked; its certificate is no longer accepted.
func (s *Store) RevokeHost(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE hosts SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE commands SET status = 'expired' WHERE host_id = ? AND status = 'queued'`, id)
	return err
}

// EnsureNetworkHost returns the network-device host for a syslog source IP, creating it
// on first sight, and refreshes last_seen.
func (s *Store) EnsureNetworkHost(ctx context.Context, sourceIP, name, vendor string) (*Host, error) {
	h, err := scanHost(s.db.QueryRowContext(ctx,
		`SELECT `+hostCols+` FROM hosts h WHERE h.kind = 'network' AND h.source_ip = ?`, sourceIP))
	if err == nil {
		if name != "" && name != h.Hostname {
			_, _ = s.db.ExecContext(ctx, `UPDATE hosts SET hostname = ? WHERE id = ?`, name, h.ID)
			h.Hostname = name
		}
		return h, s.TouchHost(ctx, h.ID)
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if name == "" {
		name = sourceIP
	}
	info := api.HostInfo{Hostname: name, OS: event.OS{Platform: "network", Name: vendor}, IPs: []string{sourceIP}}
	id := event.NewID()
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO hosts(id, kind, hostname, platform, info, labels, enrolled_at, last_seen, source_ip)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		id, HostNetwork, name, "network", mustJSON(info), `[]`, ts(now), ts(now), sourceIP)
	if err != nil {
		return nil, err
	}
	return s.GetHost(ctx, id)
}

// HostCounts returns total, online and isolated endpoint+network host counts.
func (s *Store) HostCounts(ctx context.Context) (total, online, isolated int, err error) {
	hosts, err := s.ListHosts(ctx, HostFilter{})
	if err != nil {
		return 0, 0, 0, err
	}
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		total++
		switch h.Status {
		case "online":
			online++
		case "isolated":
			isolated++
			if h.LastSeen != nil && time.Since(*h.LastSeen) < EndpointOnlineWindow {
				online++
			}
		}
	}
	return total, online, isolated, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func anyFold(have, want []string) bool {
	for _, w := range want {
		if containsFold(have, w) {
			return true
		}
	}
	return false
}
