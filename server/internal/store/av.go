package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const avSchema = `
CREATE TABLE IF NOT EXISTS av_verdicts (
	sha256 TEXT PRIMARY KEY,
	verdict TEXT NOT NULL,
	source TEXT NOT NULL,
	signature TEXT NOT NULL DEFAULT '',
	path TEXT NOT NULL DEFAULT '',
	host_id TEXT NOT NULL DEFAULT '',
	checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS av_verdicts_verdict ON av_verdicts(verdict, checked_at);
`

func init() { featureSchemas = append(featureSchemas, avSchema) }

// AV verdicts.
const (
	AVMalicious = "malicious"
	AVClean     = "clean"   // scanned, nothing found
	AVKnown     = "known"   // a known-good file (software distributions, NSRL)
	AVSkipped   = "skipped" // could not be scanned (too large, gone, not allowed)
)

// AVVerdict is the antivirus' answer for one file hash.
type AVVerdict struct {
	SHA256    string    `json:"sha256"`
	Verdict   string    `json:"verdict"`
	Source    string    `json:"source"` // blocklist, intel, clamav, ...
	Signature string    `json:"signature,omitempty"`
	Path      string    `json:"path,omitempty"` // where it was first seen
	HostID    string    `json:"host_id,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	// AuthSHA256 and AuthSHA1 are a Windows PE file's Authenticode hashes, for App
	// Control rules; empty when unknown or not a PE file.
	AuthSHA256 string `json:"auth_sha256,omitempty"`
	AuthSHA1   string `json:"auth_sha1,omitempty"`
}

// GetAVVerdict returns the stored verdict for a hash, or ErrNotFound.
func (s *Store) GetAVVerdict(ctx context.Context, sha256 string) (*AVVerdict, error) {
	v := &AVVerdict{SHA256: sha256}
	var at string
	err := s.db.QueryRowContext(ctx, `SELECT verdict, source, signature, path, host_id, checked_at, auth_sha256, auth_sha1 FROM av_verdicts WHERE sha256 = ?`, sha256).
		Scan(&v.Verdict, &v.Source, &v.Signature, &v.Path, &v.HostID, &at, &v.AuthSHA256, &v.AuthSHA1)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v.CheckedAt = parseTS(at)
	return v, nil
}

// PutAVVerdict stores or replaces the verdict for a hash.
func (s *Store) PutAVVerdict(ctx context.Context, v *AVVerdict) error {
	if v.CheckedAt.IsZero() {
		v.CheckedAt = time.Now().UTC()
	}
	// Authenticode hashes are kept when a later verdict does not carry them.
	_, err := s.db.ExecContext(ctx, `INSERT INTO av_verdicts(sha256, verdict, source, signature, path, host_id, checked_at, auth_sha256, auth_sha1)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(sha256) DO UPDATE SET verdict = excluded.verdict, source = excluded.source, signature = excluded.signature,
		path = excluded.path, host_id = excluded.host_id, checked_at = excluded.checked_at,
		auth_sha256 = CASE WHEN excluded.auth_sha256 != '' THEN excluded.auth_sha256 ELSE auth_sha256 END,
		auth_sha1 = CASE WHEN excluded.auth_sha1 != '' THEN excluded.auth_sha1 ELSE auth_sha1 END`,
		v.SHA256, v.Verdict, v.Source, v.Signature, v.Path, v.HostID, ts(v.CheckedAt), v.AuthSHA256, v.AuthSHA1)
	return err
}

// AVBlockList returns the malicious files with Authenticode hashes, oldest first, for
// App Control. Sources in skipSources (hacking tools, suspicious traits) are left out.
func (s *Store) AVBlockList(ctx context.Context, skipSources []string, limit int) ([]*AVVerdict, error) {
	q := `SELECT sha256, verdict, source, signature, path, host_id, checked_at, auth_sha256, auth_sha1 FROM av_verdicts
		WHERE verdict = ? AND auth_sha256 != ''`
	args := []any{AVMalicious}
	if len(skipSources) > 0 {
		q += ` AND source NOT IN (` + placeholders(len(skipSources)) + `)`
		for _, v := range skipSources {
			args = append(args, v)
		}
	}
	q += ` ORDER BY sha256 LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AVVerdict
	for rows.Next() {
		v := &AVVerdict{}
		var at string
		if err := rows.Scan(&v.SHA256, &v.Verdict, &v.Source, &v.Signature, &v.Path, &v.HostID, &at, &v.AuthSHA256, &v.AuthSHA1); err != nil {
			return nil, err
		}
		v.CheckedAt = parseTS(at)
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteAVVerdict forgets a hash, so it is checked again the next time it is seen.
func (s *Store) DeleteAVVerdict(ctx context.Context, sha256 string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM av_verdicts WHERE sha256 = ?`, sha256)
	return err
}

// AVVerdictCounts counts stored verdicts by kind.
func (s *Store) AVVerdictCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT verdict, COUNT(*) FROM av_verdicts GROUP BY verdict`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// AVDetections returns the newest malicious verdicts.
func (s *Store) AVDetections(ctx context.Context, limit int) ([]*AVVerdict, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sha256, verdict, source, signature, path, host_id, checked_at FROM av_verdicts
		WHERE verdict = ? ORDER BY checked_at DESC LIMIT ?`, AVMalicious, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AVVerdict
	for rows.Next() {
		v := &AVVerdict{}
		var at string
		if err := rows.Scan(&v.SHA256, &v.Verdict, &v.Source, &v.Signature, &v.Path, &v.HostID, &at); err != nil {
			return nil, err
		}
		v.CheckedAt = parseTS(at)
		out = append(out, v)
	}
	return out, rows.Err()
}
