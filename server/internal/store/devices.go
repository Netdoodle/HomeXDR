package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

const devicesSchema = `
CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	mac TEXT NOT NULL DEFAULT '',
	macs TEXT NOT NULL DEFAULT '[]',
	randomized INTEGER NOT NULL DEFAULT 0,
	ip TEXT NOT NULL DEFAULT '',
	ips TEXT NOT NULL DEFAULT '[]',
	hostname TEXT NOT NULL DEFAULT '',
	hostnames TEXT NOT NULL DEFAULT '[]',
	vendor TEXT NOT NULL DEFAULT '',
	subnet TEXT NOT NULL DEFAULT '',
	interface TEXT NOT NULL DEFAULT '',
	sources TEXT NOT NULL DEFAULT '[]',
	host_id TEXT NOT NULL DEFAULT '',
	host_name TEXT NOT NULL DEFAULT '',
	name TEXT NOT NULL DEFAULT '',
	note TEXT NOT NULL DEFAULT '',
	known INTEGER NOT NULL DEFAULT 0,
	dest_only INTEGER NOT NULL DEFAULT 0,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	alerted_at TEXT
);
`

func init() { featureSchemas = append(featureSchemas, devicesSchema) }

// DeviceIP is one address a device has used.
type DeviceIP struct {
	IP        string    `json:"ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Device is one device on the home network. Its ID is its first MAC address, or
// "ip:<address>" until DHCP reveals a MAC.
type Device struct {
	ID string `json:"id"`
	// MAC is empty on a provisional record: an address with no MAC known yet.
	MAC  string   `json:"mac,omitempty"`
	MACs []string `json:"macs,omitempty"`
	// Randomized reports a locally administered MAC, as phones use for privacy.
	Randomized bool       `json:"randomized_mac,omitempty"`
	IP         string     `json:"ip,omitempty"`
	IPs        []DeviceIP `json:"ips"`
	// Hostname is the latest name the device gave DHCP; Hostnames keeps earlier ones.
	Hostname  string   `json:"hostname,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Subnet    string   `json:"subnet,omitempty"`
	Interface string   `json:"interface,omitempty"`
	// Sources lists what has seen the device: dhcp, firewall, netflow, dns, suricata, agent.
	Sources []string `json:"sources"`
	// HostID and HostName link the device to the agent running on it.
	HostID   string `json:"host_id,omitempty"`
	HostName string `json:"host_name,omitempty"`
	// Name and Note are set by the owner.
	Name string `json:"name,omitempty"`
	Note string `json:"note,omitempty"`
	// Known is set by the owner: this device is expected here.
	Known bool `json:"known"`
	// DestOnly reports an address only ever seen receiving traffic, never sending it. A
	// sweep of a subnet produces these, so they are not evidence of a device.
	DestOnly  bool       `json:"dest_only,omitempty"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	AlertedAt *time.Time `json:"alerted_at,omitempty"`
}

// ListDevices returns every device.
func (s *Store) ListDevices(ctx context.Context) ([]*Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, mac, macs, randomized, ip, ips, hostname, hostnames, vendor, subnet,
		interface, sources, host_id, host_name, name, note, known, dest_only, first_seen, last_seen, alerted_at FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d := &Device{}
		var macs, ips, hostnames, sources, first, last string
		var alerted sql.NullString
		if err := rows.Scan(&d.ID, &d.MAC, &macs, &d.Randomized, &d.IP, &ips, &d.Hostname, &hostnames, &d.Vendor, &d.Subnet,
			&d.Interface, &sources, &d.HostID, &d.HostName, &d.Name, &d.Note, &d.Known, &d.DestOnly, &first, &last, &alerted); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(macs), &d.MACs)
		_ = json.Unmarshal([]byte(ips), &d.IPs)
		_ = json.Unmarshal([]byte(hostnames), &d.Hostnames)
		_ = json.Unmarshal([]byte(sources), &d.Sources)
		d.FirstSeen, d.LastSeen, d.AlertedAt = parseTS(first), parseTS(last), parseNullTS(alerted)
		out = append(out, d)
	}
	return out, rows.Err()
}

// SaveDevices writes changed devices and removes deleted ones in one transaction.
func (s *Store) SaveDevices(ctx context.Context, changed []*Device, deleted []string) error {
	if len(changed) == 0 && len(deleted) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range deleted {
		if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id); err != nil {
			return err
		}
	}
	for _, d := range changed {
		_, err := tx.ExecContext(ctx, `INSERT INTO devices(id, mac, macs, randomized, ip, ips, hostname, hostnames, vendor, subnet,
			interface, sources, host_id, host_name, name, note, known, dest_only, first_seen, last_seen, alerted_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET mac=excluded.mac, macs=excluded.macs, randomized=excluded.randomized, ip=excluded.ip,
			ips=excluded.ips, hostname=excluded.hostname, hostnames=excluded.hostnames, vendor=excluded.vendor, subnet=excluded.subnet,
			interface=excluded.interface, sources=excluded.sources, host_id=excluded.host_id, host_name=excluded.host_name,
			name=excluded.name, note=excluded.note, known=excluded.known, dest_only=excluded.dest_only,
			first_seen=excluded.first_seen, last_seen=excluded.last_seen, alerted_at=excluded.alerted_at`,
			d.ID, d.MAC, mustJSON(d.MACs), d.Randomized, d.IP, mustJSON(d.IPs), d.Hostname, mustJSON(d.Hostnames), d.Vendor, d.Subnet,
			d.Interface, mustJSON(d.Sources), d.HostID, d.HostName, d.Name, d.Note, d.Known, d.DestOnly, ts(d.FirstSeen), ts(d.LastSeen), nullTS(d.AlertedAt))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
