package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
	"golang.org/x/crypto/bcrypt"
)

// Roles.
const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleViewer  = "viewer"
)

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool {
	return r == RoleAdmin || r == RoleAnalyst || r == RoleViewer
}

// RoleAtLeast reports whether role has at least the privileges of min.
func RoleAtLeast(role, min string) bool {
	rank := map[string]int{RoleViewer: 1, RoleAnalyst: 2, RoleAdmin: 3}
	return rank[role] >= rank[min] && rank[min] > 0
}

// User is a console account.
type User struct {
	ID        string     `json:"id"`
	Username  string     `json:"username"`
	Role      string     `json:"role"`
	CreatedAt time.Time  `json:"created_at"`
	LastLogin *time.Time `json:"last_login,omitempty"`
}

// MinPasswordLen is the minimum console password length.
const MinPasswordLen = 10

// ErrWeakPassword is returned for passwords shorter than MinPasswordLen.
var ErrWeakPassword = errors.New("password must be at least 10 characters")

// HashPassword hashes a password with bcrypt.
func HashPassword(pw string) (string, error) {
	if len(pw) < MinPasswordLen {
		return "", ErrWeakPassword
	}
	if len(pw) > 72 {
		return "", errors.New("password must be at most 72 bytes")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(b), err
}

// CountUsers returns the number of users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser adds a user. It returns ErrConflict if the username is taken.
func (s *Store) CreateUser(ctx context.Context, username, password, role string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 {
		return nil, errors.New("username must be 1-64 characters")
	}
	if !ValidRole(role) {
		return nil, errors.New("invalid role")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	u := &User{ID: event.NewID(), Username: username, Role: role, CreatedAt: time.Now().UTC()}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users(id, username, password_hash, role, created_at) VALUES(?,?,?,?,?)`,
		u.ID, u.Username, hash, u.Role, ts(u.CreatedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrConflict
		}
		return nil, err
	}
	return u, nil
}

// CreateFirstUser creates the initial admin only if no users exist, atomically.
func (s *Store) CreateFirstUser(ctx context.Context, username, password string) (*User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 {
		return nil, errors.New("username must be 1-64 characters")
	}
	u := &User{ID: event.NewID(), Username: username, Role: RoleAdmin, CreatedAt: time.Now().UTC()}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users(id, username, password_hash, role, created_at)
		 SELECT ?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM users)`,
		u.ID, u.Username, hash, u.Role, ts(u.CreatedAt))
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrConflict
	}
	return u, nil
}

func scanUser(row interface{ Scan(...any) error }) (*User, string, error) {
	var u User
	var hash, created string
	var last sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &hash, &u.Role, &created, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}
	u.CreatedAt = parseTS(created)
	u.LastLogin = parseNullTS(last)
	return &u, hash, nil
}

const userCols = `id, username, password_hash, role, created_at, last_login`

// Authenticate checks a username and password. It returns ErrNotFound for any failure,
// and does a dummy bcrypt comparison for unknown users to keep timing similar.
func (s *Store) Authenticate(ctx context.Context, username, password string) (*User, error) {
	u, hash, err := scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE username = ?`, strings.TrimSpace(username)))
	if errors.Is(err, ErrNotFound) {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	_, _ = s.db.ExecContext(ctx, `UPDATE users SET last_login = ? WHERE id = ?`, ts(now), u.ID)
	u.LastLogin = &now
	return u, nil
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("homexdr-dummy-password"), 12)

// GetUser returns a user by ID.
func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	u, _, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	return u, err
}

// ListUsers returns all users ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, _, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser changes a user's role and/or password (empty values are left unchanged).
// Changing the password invalidates the user's sessions.
func (s *Store) UpdateUser(ctx context.Context, id, role, password string) (*User, error) {
	if role != "" {
		if !ValidRole(role) {
			return nil, errors.New("invalid role")
		}
		if role != RoleAdmin {
			// Never demote the last admin.
			var admins int
			if err := s.db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?`, id).Scan(&admins); err != nil {
				return nil, err
			}
			cur, err := s.GetUser(ctx, id)
			if err != nil {
				return nil, err
			}
			if cur.Role == RoleAdmin && admins == 0 {
				return nil, errors.New("cannot demote the last admin")
			}
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id); err != nil {
			return nil, err
		}
	}
	if password != "" {
		hash, err := HashPassword(password)
		if err != nil {
			return nil, err
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id); err != nil {
			return nil, err
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return nil, err
		}
	}
	return s.GetUser(ctx, id)
}

// DeleteUser removes a user. The last admin cannot be deleted.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	u, err := s.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if u.Role == RoleAdmin {
		var admins int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&admins); err != nil {
			return err
		}
		if admins <= 1 {
			return errors.New("cannot delete the last admin")
		}
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// SessionTTL is how long a console session lasts.
const SessionTTL = 12 * time.Hour

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// RandomToken returns n random bytes, base64url encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// CreateSession starts a session for a user and returns the cookie value.
func (s *Store) CreateSession(ctx context.Context, userID string) (string, time.Time, error) {
	tok := RandomToken(32)
	now := time.Now().UTC()
	exp := now.Add(SessionTTL)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(token_hash, user_id, created_at, expires_at) VALUES(?,?,?,?)`,
		hashToken(tok), userID, ts(now), ts(exp))
	return tok, exp, err
}

// SessionUser returns the user for a session cookie value, or ErrNotFound.
func (s *Store) SessionUser(ctx context.Context, tok string) (*User, error) {
	if tok == "" {
		return nil, ErrNotFound
	}
	u, _, err := scanUser(s.db.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.password_hash, u.role, u.created_at, u.last_login
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = ? AND s.expires_at > ?`, hashToken(tok), ts(time.Now())))
	return u, err
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, tok string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hashToken(tok))
	return err
}

// PurgeExpired deletes expired sessions.
func (s *Store) PurgeExpired(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, ts(time.Now()))
	return err
}
