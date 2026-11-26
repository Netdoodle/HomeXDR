package store

import (
	"context"
	"database/sql"
	"errors"
)

// RemoveHost deletes a host and everything keyed only by it, in one transaction: its
// commands and their result rows, vulnerability findings and matches, and feed-source
// state. The host row carries its labels and group membership, so they go with it.
// Stored events and alerts stay (alerts keep the hostname they were raised with).
//
// Agent identities are random IDs minted at enrolment and a certificate's subject is that
// ID, so once the row is gone the agent's certificate no longer matches any host: it is
// refused as an unknown agent, and enrolling again needs a token and makes a new host.
//
// It returns the paths of files the host's commands had uploaded, for the caller to
// delete once the transaction has committed.
func (s *Store) RemoveHost(ctx context.Context, id string) (uploads []string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM hosts WHERE id = ?`, id).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT upload_path FROM commands WHERE host_id = ? AND upload_path != ''`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return nil, err
		}
		uploads = append(uploads, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	for _, q := range []string{
		`DELETE FROM command_rows WHERE host_id = ?`,
		`DELETE FROM commands WHERE host_id = ?`,
		`DELETE FROM vuln_findings WHERE host_id = ?`,
		`DELETE FROM vuln_matches WHERE host_id = ?`,
		`DELETE FROM feed_sources WHERE host_id = ?`,
		`DELETE FROM hosts WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return uploads, nil
}
