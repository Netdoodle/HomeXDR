package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

func init() { featureSchemas = append(featureSchemas, vulnFindingsSchema) }

// Vulnerability findings live on the Vulnerabilities page, not in the alert queue. Each row is
// one CVE in one package on one host; data holds the details as JSON, and the columns are the
// state HomeXDR keeps across scans.
const vulnFindingsSchema = `
CREATE TABLE IF NOT EXISTS vuln_findings (
	host_id TEXT NOT NULL,
	package TEXT NOT NULL,
	cve TEXT NOT NULL,
	status TEXT NOT NULL,
	accepted_note TEXT NOT NULL DEFAULT '',
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	fixed_at TEXT,
	data TEXT NOT NULL DEFAULT '{}',
	PRIMARY KEY (host_id, package, cve)
);
CREATE TABLE IF NOT EXISTS vuln_history (
	date TEXT PRIMARY KEY,
	critical INTEGER NOT NULL DEFAULT 0,
	high INTEGER NOT NULL DEFAULT 0,
	medium INTEGER NOT NULL DEFAULT 0,
	low INTEGER NOT NULL DEFAULT 0,
	new INTEGER NOT NULL DEFAULT 0,
	fixed INTEGER NOT NULL DEFAULT 0
);
`

// Statuses of a vulnerability finding.
const (
	VulnOpen     = "open"
	VulnFixed    = "fixed"
	VulnAccepted = "accepted"
)

// VulnFinding is one CVE in one package on one host.
type VulnFinding struct {
	ID            string   `json:"id"`
	HostID        string   `json:"host_id"`
	Hostname      string   `json:"hostname"`
	Package       string   `json:"package"`
	SourcePackage string   `json:"source_package"`
	Version       string   `json:"version"`
	PackageType   string   `json:"package_type"`
	CVE           string   `json:"cve"`
	Title         string   `json:"title"`
	Summary       string   `json:"summary"`
	FixedVersion  string   `json:"fixed_version"`
	CVSS          *float64 `json:"cvss"`
	CVSSVector    string   `json:"cvss_vector"`
	// SeveritySource is osv (a CVSS vector), distro (the distribution's rating) or estimated.
	SeveritySource    string   `json:"severity_source"`
	EPSS              *float64 `json:"epss"`
	EPSSPercentile    *float64 `json:"epss_percentile"`
	KEV               bool     `json:"kev"`
	KEVDueDate        string   `json:"kev_due_date"`
	Ransomware        bool     `json:"ransomware"`
	Exposure          string   `json:"exposure"`
	ExposedPorts      []int    `json:"exposed_ports"`
	AttackVector      string   `json:"attack_vector"`
	Likelihood        float64  `json:"likelihood"`
	Risk              float64  `json:"risk"`
	Band              string   `json:"band"`
	LikelihoodReasons []string `json:"likelihood_reasons"`
	// Confidence is confirmed when a version check agrees, possible for a name match only.
	Confidence   string     `json:"confidence"`
	Status       string     `json:"status"`
	AcceptedNote string     `json:"accepted_note"`
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     time.Time  `json:"last_seen"`
	FixedAt      *time.Time `json:"fixed_at,omitempty"`
}

// VulnKey is a finding's stable ID.
func VulnKey(hostID, pkg, cve string) string { return hostID + "|" + pkg + "|" + cve }

// ListVulnFindings returns every stored finding, riskiest first.
func (s *Store) ListVulnFindings(ctx context.Context) ([]VulnFinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, package, cve, status, accepted_note, first_seen, last_seen, fixed_at, data FROM vuln_findings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnFinding{}
	for rows.Next() {
		var f VulnFinding
		var hostID, pkg, cve, status, note, data string
		var first, last, fixed sql.NullString
		if err := rows.Scan(&hostID, &pkg, &cve, &status, &note, &first, &last, &fixed, &data); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(data), &f)
		f.HostID, f.SourcePackage, f.CVE, f.Status, f.AcceptedNote = hostID, pkg, cve, status, note
		f.ID = VulnKey(hostID, pkg, cve)
		f.FirstSeen, f.LastSeen = nullToZero(first), nullToZero(last)
		if t := nullToZero(fixed); !t.IsZero() {
			f.FixedAt = &t
		} else {
			f.FixedAt = nil
		}
		if f.ExposedPorts == nil {
			f.ExposedPorts = []int{}
		}
		if f.LikelihoodReasons == nil {
			f.LikelihoodReasons = []string{}
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ReplaceVulnFindings makes list a host's findings, in one transaction. SourcePackage is the
// row's package key.
func (s *Store) ReplaceVulnFindings(ctx context.Context, hostID string, list []VulnFinding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_findings WHERE host_id = ?`, hostID); err != nil {
		return err
	}
	for i := range list {
		f := &list[i]
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		var fixed any
		if f.FixedAt != nil {
			fixed = ts(*f.FixedAt)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_findings(host_id, package, cve, status, accepted_note, first_seen, last_seen, fixed_at, data)
			VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id, package, cve) DO NOTHING`,
			hostID, f.SourcePackage, f.CVE, f.Status, f.AcceptedNote, ts(f.FirstSeen), ts(f.LastSeen), fixed, string(data)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetVulnAccepted marks an open finding as an accepted risk, with a note, or undoes that.
func (s *Store) SetVulnAccepted(ctx context.Context, hostID, pkg, cve string, accepted bool, note string) error {
	var res sql.Result
	var err error
	if accepted {
		res, err = s.db.ExecContext(ctx, `UPDATE vuln_findings SET status = ?, accepted_note = ? WHERE host_id = ? AND package = ? AND cve = ? AND status != ?`,
			VulnAccepted, note, hostID, pkg, cve, VulnFixed)
	} else {
		res, err = s.db.ExecContext(ctx, `UPDATE vuln_findings SET status = ?, accepted_note = '' WHERE host_id = ? AND package = ? AND cve = ? AND status = ?`,
			VulnOpen, hostID, pkg, cve, VulnAccepted)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// VulnHistoryPoint is one day of the Vulnerabilities page's charts.
type VulnHistoryPoint struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	New      int    `json:"new"`
	Fixed    int    `json:"fixed"`
}

// SaveVulnHistory stores a day's counts, replacing that day's earlier ones.
func (s *Store) SaveVulnHistory(ctx context.Context, p VulnHistoryPoint) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vuln_history(date, critical, high, medium, low, new, fixed) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(date) DO UPDATE SET critical = excluded.critical, high = excluded.high, medium = excluded.medium,
		low = excluded.low, new = excluded.new, fixed = excluded.fixed`, p.Date, p.Critical, p.High, p.Medium, p.Low, p.New, p.Fixed)
	return err
}

// ListVulnHistory returns the days from since on, oldest first, and forgets older ones.
func (s *Store) ListVulnHistory(ctx context.Context, since string) ([]VulnHistoryPoint, error) {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM vuln_history WHERE date < ?`, since); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT date, critical, high, medium, low, new, fixed FROM vuln_history WHERE date >= ? ORDER BY date`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnHistoryPoint{}
	for rows.Next() {
		var p VulnHistoryPoint
		if err := rows.Scan(&p.Date, &p.Critical, &p.High, &p.Medium, &p.Low, &p.New, &p.Fixed); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ResolveRuleAlerts resolves every open alert of a rule, with a note. It returns how many.
func (s *Store) ResolveRuleAlerts(ctx context.Context, ruleID, author, note string) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM alerts WHERE rule_id = ? AND status IN ('new','in_progress')`, ruleID)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	resolved := AlertResolved
	for _, id := range ids {
		if _, err := s.AddAlertNote(ctx, id, author, note); err != nil {
			return 0, err
		}
		if _, err := s.UpdateAlert(ctx, id, &resolved, nil); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}
