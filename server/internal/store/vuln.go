package store

import (
	"context"
	"database/sql"
	"time"
)

func init() { featureSchemas = append(featureSchemas, vulnSchema) }

const vulnSchema = `
CREATE TABLE IF NOT EXISTS vuln_matches (
	host_id TEXT NOT NULL,
	package TEXT NOT NULL,
	cve TEXT NOT NULL,
	hostname TEXT NOT NULL DEFAULT '',
	version TEXT NOT NULL DEFAULT '',
	package_type TEXT NOT NULL DEFAULT '',
	title TEXT NOT NULL DEFAULT '',
	kev_date TEXT NOT NULL DEFAULT '',
	due_date TEXT NOT NULL DEFAULT '',
	ransomware INTEGER NOT NULL DEFAULT 0,
	confidence TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	raised INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (host_id, package, cve)
);
`

// VulnMatch is installed software on a host that matches a known-exploited vulnerability.
type VulnMatch struct {
	HostID      string `json:"host_id"`
	Hostname    string `json:"hostname"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	PackageType string `json:"package_type"`
	CVE         string `json:"cve"`
	Title       string `json:"title"`
	// KEVDate is when CISA added it, and DueDate its deadline for U.S. agencies.
	KEVDate    string `json:"kev_date"`
	DueDate    string `json:"due_date"`
	Ransomware bool   `json:"ransomware"`
	// Confidence is "confirmed" when a version check agrees, otherwise "possible".
	Confidence string    `json:"confidence"`
	Reason     string    `json:"reason"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	// Raised says an alert was raised for this host and CVE.
	Raised bool `json:"-"`
}

// ListVulnMatches returns every match, confirmed first, then newest on the catalog.
func (s *Store) ListVulnMatches(ctx context.Context) ([]VulnMatch, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, package, cve, hostname, version, package_type, title, kev_date, due_date,
		ransomware, confidence, reason, first_seen, last_seen, raised FROM vuln_matches
		ORDER BY confidence = 'confirmed' DESC, ransomware DESC, kev_date DESC, hostname, package, cve`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnMatch{}
	for rows.Next() {
		var m VulnMatch
		var ransomware, raised int
		var first, last sql.NullString
		if err := rows.Scan(&m.HostID, &m.Package, &m.CVE, &m.Hostname, &m.Version, &m.PackageType, &m.Title, &m.KEVDate, &m.DueDate,
			&ransomware, &m.Confidence, &m.Reason, &first, &last, &raised); err != nil {
			return nil, err
		}
		m.Ransomware, m.Raised = ransomware != 0, raised != 0
		m.FirstSeen, m.LastSeen = nullToZero(first), nullToZero(last)
		out = append(out, m)
	}
	return out, rows.Err()
}

// ReplaceVulnMatches makes list the host's matches, in one transaction.
func (s *Store) ReplaceVulnMatches(ctx context.Context, hostID string, list []VulnMatch) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_matches WHERE host_id = ?`, hostID); err != nil {
		return err
	}
	for i := range list {
		m := &list[i]
		if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_matches(host_id, package, cve, hostname, version, package_type, title,
			kev_date, due_date, ransomware, confidence, reason, first_seen, last_seen, raised) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(host_id, package, cve) DO NOTHING`,
			hostID, m.Package, m.CVE, m.Hostname, m.Version, m.PackageType, m.Title, m.KEVDate, m.DueDate, boolInt(m.Ransomware),
			m.Confidence, m.Reason, ts(m.FirstSeen), ts(m.LastSeen), boolInt(m.Raised)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
