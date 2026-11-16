package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

// RecoveryCodeCount is how many recovery codes a user gets at a time.
const RecoveryCodeCount = 10

const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewRecoveryCodes returns n random recovery codes formatted xxxx-xxxx-xxxx.
func NewRecoveryCodes(n int) []string {
	max := big.NewInt(int64(len(recoveryAlphabet)))
	out := make([]string, n)
	for i := range out {
		var b strings.Builder
		for j := 0; j < 12; j++ {
			if j > 0 && j%4 == 0 {
				b.WriteByte('-')
			}
			k, err := rand.Int(rand.Reader, max)
			if err != nil {
				panic(err)
			}
			b.WriteByte(recoveryAlphabet[k.Int64()])
		}
		out[i] = b.String()
	}
	return out
}

// IsRecoveryCode reports whether s looks like a recovery code (xxxx-xxxx-xxxx).
func IsRecoveryCode(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 14 || s[4] != '-' || s[9] != '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 4 || i == 9 {
			continue
		}
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// HashRecoveryCode is the stored form of a recovery code: SHA-256 hex of the lowercased code.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(code))))
	return hex.EncodeToString(sum[:])
}

// HashRecoveryCodes hashes a list of codes.
func HashRecoveryCodes(codes []string) []string {
	out := make([]string, len(codes))
	for i, c := range codes {
		out[i] = HashRecoveryCode(c)
	}
	return out
}

// TOTPState is a user's two-factor state, for the server's own use only.
type TOTPState struct {
	Secret       string
	Enabled      bool
	LastStep     int64
	RecoveryLeft int
}

func parseRecovery(s string) []string {
	var out []string
	if s != "" {
		_ = json.Unmarshal([]byte(s), &out)
	}
	return out
}

// GetTOTP returns a user's two-factor state.
func (s *Store) GetTOTP(ctx context.Context, userID string) (*TOTPState, error) {
	var st TOTPState
	var on int
	var rec string
	err := s.db.QueryRowContext(ctx,
		`SELECT totp_secret, totp_enabled, totp_last_step, totp_recovery FROM users WHERE id = ?`, userID).
		Scan(&st.Secret, &on, &st.LastStep, &rec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	st.Enabled = on != 0
	st.RecoveryLeft = len(parseRecovery(rec))
	return &st, nil
}

// SetTOTPPending stores a new secret without turning two-factor on. It refuses when
// two-factor is already on.
func (s *Store) SetTOTPPending(ctx context.Context, userID, secret string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = ?, totp_last_step = 0 WHERE id = ? AND totp_enabled = 0`, secret, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	return nil
}

// EnableTOTP turns two-factor on for a user with a pending secret, storing the hashes of
// the recovery codes and the step of the code that confirmed it.
func (s *Store) EnableTOTP(ctx context.Context, userID string, recoveryHashes []string, step int64) error {
	b, _ := json.Marshal(recoveryHashes)
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_enabled = 1, totp_recovery = ?, totp_last_step = ?
		 WHERE id = ? AND totp_enabled = 0 AND totp_secret != ''`, string(b), step, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	return nil
}

// DisableTOTP turns two-factor off and clears the secret, step and recovery codes.
func (s *Store) DisableTOTP(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = '', totp_enabled = 0, totp_last_step = 0, totp_recovery = '' WHERE id = ?`, userID)
	return err
}

// UseTOTPStep records step as the last one used. It returns false when a step at or after
// it was already recorded, which closes the race between two requests with the same code.
func (s *Store) UseTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, userID, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ReplaceRecovery swaps in a new set of recovery code hashes (two-factor must be on).
func (s *Store) ReplaceRecovery(ctx context.Context, userID string, hashes []string) error {
	b, _ := json.Marshal(hashes)
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_recovery = ? WHERE id = ? AND totp_enabled = 1`, string(b), userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	return nil
}

// ConsumeRecovery removes a recovery code's hash if it is present and reports whether it
// was, and how many codes remain. The removal is compare-and-swap, so a code used twice at
// the same time works once.
func (s *Store) ConsumeRecovery(ctx context.Context, userID, hash string) (bool, int, error) {
	for attempt := 0; attempt < 5; attempt++ {
		var cur string
		err := s.db.QueryRowContext(ctx, `SELECT totp_recovery FROM users WHERE id = ?`, userID).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) {
			return false, 0, ErrNotFound
		}
		if err != nil {
			return false, 0, err
		}
		list := parseRecovery(cur)
		idx := -1
		for i, h := range list {
			if h == hash {
				idx = i
			}
		}
		if idx < 0 {
			return false, len(list), nil
		}
		list = append(list[:idx], list[idx+1:]...)
		b, _ := json.Marshal(list)
		res, err := s.db.ExecContext(ctx,
			`UPDATE users SET totp_recovery = ? WHERE id = ? AND totp_recovery = ?`, string(b), userID, cur)
		if err != nil {
			return false, 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return true, len(list), nil
		}
	}
	return false, 0, errors.New("recovery codes changed concurrently")
}
