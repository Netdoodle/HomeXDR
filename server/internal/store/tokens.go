package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// EnrollmentToken is an agent enrollment token. Token is only set when created.
type EnrollmentToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Token     string     `json:"token,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy string     `json:"created_by"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	MaxUses   *int       `json:"max_uses,omitempty"`
	Uses      int        `json:"uses"`
	Labels    []string   `json:"labels"`
}

// Enrollment token errors.
var (
	ErrTokenInvalid = errors.New("enrollment token is invalid or expired")
	ErrTokenUsedUp  = errors.New("enrollment token has no uses left")
)

// CreateToken creates an enrollment token. The plaintext token is returned once.
func (s *Store) CreateToken(ctx context.Context, name, createdBy string, expires *time.Time, maxUses *int, labels []string) (*EnrollmentToken, error) {
	if labels == nil {
		labels = []string{}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "token"
	}
	t := &EnrollmentToken{
		ID: event.NewID(), Name: name, Token: "hxe_" + RandomToken(24),
		CreatedAt: time.Now().UTC(), CreatedBy: createdBy, ExpiresAt: expires, MaxUses: maxUses, Labels: labels,
	}
	var mu any
	if maxUses != nil {
		mu = *maxUses
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO enrollment_tokens(id, name, token_hash, created_at, created_by, expires_at, max_uses, labels)
		 VALUES(?,?,?,?,?,?,?,?)`,
		t.ID, t.Name, hashToken(t.Token), ts(t.CreatedAt), createdBy, nullTS(expires), mu, mustJSON(labels))
	if err != nil {
		return nil, err
	}
	return t, nil
}

func scanToken(row interface{ Scan(...any) error }) (*EnrollmentToken, error) {
	var t EnrollmentToken
	var created, labels string
	var exp sql.NullString
	var maxUses sql.NullInt64
	if err := row.Scan(&t.ID, &t.Name, &created, &t.CreatedBy, &exp, &maxUses, &t.Uses, &labels); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt = parseTS(created)
	t.ExpiresAt = parseNullTS(exp)
	if maxUses.Valid {
		n := int(maxUses.Int64)
		t.MaxUses = &n
	}
	unmarshalJSON(labels, &t.Labels)
	if t.Labels == nil {
		t.Labels = []string{}
	}
	return &t, nil
}

const tokenCols = `id, name, created_at, created_by, expires_at, max_uses, uses, labels`

// ListTokens returns all tokens, newest first.
func (s *Store) ListTokens(ctx context.Context) ([]*EnrollmentToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*EnrollmentToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteToken removes a token.
func (s *Store) DeleteToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM enrollment_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UseToken validates a plaintext token and consumes one use atomically.
func (s *Store) UseToken(ctx context.Context, plaintext string) (*EnrollmentToken, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx,
		`SELECT `+tokenCols+` FROM enrollment_tokens WHERE token_hash = ?`, hashToken(plaintext)))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return nil, ErrTokenInvalid
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE enrollment_tokens SET uses = uses + 1 WHERE id = ? AND (max_uses IS NULL OR uses < max_uses)`, t.ID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrTokenUsedUp
	}
	t.Uses++
	return t, nil
}
