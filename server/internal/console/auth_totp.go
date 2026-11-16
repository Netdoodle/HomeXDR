package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/totp"
)

const (
	mfaTokenTTL     = 5 * time.Minute
	mfaMaxAttempts  = 5
	mfaMaxPending   = 1000
	totpIssuer      = "HomeXDR"
	errBadCode      = "that code is not right"
	errMFAGeneric   = "invalid or expired code"
	tooManyAttempts = "too many failed attempts; try again in 15 minutes"
)

// mfaPending holds logins that passed the password step and wait for a code. They live in
// memory only: a restart just means signing in again.
type mfaPending struct {
	mu sync.Mutex
	m  map[string]*mfaEntry
}

type mfaEntry struct {
	userID   string
	ip       string
	exp      time.Time
	attempts int
}

func newMFAPending() *mfaPending { return &mfaPending{m: map[string]*mfaEntry{}} }

func (p *mfaPending) create(userID, ip string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := hex.EncodeToString(b)
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, e := range p.m {
		if now.After(e.exp) {
			delete(p.m, k)
		}
	}
	if len(p.m) >= mfaMaxPending { // bound memory: drop the oldest
		var oldest string
		var oldestExp time.Time
		for k, e := range p.m {
			if oldest == "" || e.exp.Before(oldestExp) {
				oldest, oldestExp = k, e.exp
			}
		}
		delete(p.m, oldest)
	}
	p.m[tok] = &mfaEntry{userID: userID, ip: ip, exp: now.Add(mfaTokenTTL)}
	return tok
}

// attempt validates a token for one code attempt and counts it. The token is removed
// once its attempts are used up.
func (p *mfaPending) attempt(tok, ip string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[tok]
	if !ok {
		return "", false
	}
	if time.Now().After(e.exp) || e.attempts >= mfaMaxAttempts {
		delete(p.m, tok)
		return "", false
	}
	if e.ip != ip {
		return "", false
	}
	e.attempts++
	return e.userID, true
}

func (p *mfaPending) consume(tok string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, tok)
}

// checkSecondFactor verifies a code against a user's enabled two-factor state: a TOTP
// code (never reused) or, when it has the recovery code shape, a recovery code (used once).
func (h *Handler) checkSecondFactor(ctx context.Context, userID string, st *store.TOTPState, code string) (ok, recovery bool, left int, err error) {
	if store.IsRecoveryCode(code) {
		ok, left, err = h.c.State.ConsumeRecovery(ctx, userID, store.HashRecoveryCode(code))
		return ok, true, left, err
	}
	step, good := totp.Verify(st.Secret, code, time.Now(), st.LastStep)
	if !good {
		return false, false, st.RecoveryLeft, nil
	}
	ok, err = h.c.State.UseTOTPStep(ctx, userID, step)
	return ok, false, st.RecoveryLeft, err
}

type mfaRequest struct {
	Token string `json:"mfa_token"`
	Code  string `json:"code"`
}

func (h *Handler) mfaLogin(w http.ResponseWriter, r *http.Request) {
	var req mfaRequest
	if !decode(w, r, &req) {
		return
	}
	ip := h.clientIP(r)
	userID, ok := h.mfa.attempt(req.Token, ip)
	if !ok {
		h.c.Audit(r.Context(), "", "auth.mfa_failed", "", "unknown, expired or used token from "+ip)
		writeErr(w, http.StatusUnauthorized, errMFAGeneric)
		return
	}
	key := ip + "|mfa|" + userID
	if !h.limiter.allow(key) {
		h.mfa.consume(req.Token)
		writeErr(w, http.StatusTooManyRequests, tooManyAttempts)
		return
	}
	u, err := h.c.State.GetUser(r.Context(), userID)
	if err != nil {
		h.mfa.consume(req.Token)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusUnauthorized, errMFAGeneric)
			return
		}
		h.fail(w, err)
		return
	}
	st, err := h.c.State.GetTOTP(r.Context(), userID)
	if err != nil {
		h.fail(w, err)
		return
	}
	if !st.Enabled {
		h.mfa.consume(req.Token)
		h.c.Audit(r.Context(), u.Username, "auth.mfa_failed", u.ID, "two-factor is not on, from "+ip)
		writeErr(w, http.StatusUnauthorized, errMFAGeneric)
		return
	}
	good, recovery, left, err := h.checkSecondFactor(r.Context(), userID, st, req.Code)
	if err != nil {
		h.fail(w, err)
		return
	}
	if !good {
		h.limiter.fail(key)
		kind := "code"
		if recovery {
			kind = "recovery code"
		}
		h.c.Audit(r.Context(), u.Username, "auth.mfa_failed", u.ID, "wrong "+kind+" from "+ip)
		writeErr(w, http.StatusUnauthorized, errMFAGeneric)
		return
	}
	h.mfa.consume(req.Token)
	h.limiter.reset(key)
	detail := "authenticator code from " + ip
	if recovery {
		detail = fmt.Sprintf("recovery code used from %s, %d left", ip, left)
	}
	h.c.Audit(r.Context(), u.Username, "auth.mfa", u.ID, detail)
	h.startSession(w, r, u)
}

// --- the signed-in user's own two-factor settings ---

func (h *Handler) totpStatus(w http.ResponseWriter, r *http.Request, u *store.User) {
	st, err := h.c.State.GetTOTP(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	left := 0
	if st.Enabled {
		left = st.RecoveryLeft
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": st.Enabled, "recovery_left": left})
}

// confirmPassword checks the signed-in user's password, counted like failed logins.
func (h *Handler) confirmPassword(w http.ResponseWriter, r *http.Request, u *store.User, pw string) (key string, ok bool) {
	key = h.clientIP(r) + "|" + strings.ToLower(u.Username)
	if !h.limiter.allow(key) {
		writeErr(w, http.StatusTooManyRequests, tooManyAttempts)
		return key, false
	}
	if _, err := h.c.State.Authenticate(r.Context(), u.Username, pw); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.limiter.fail(key)
			h.c.Audit(r.Context(), u.Username, "account.totp.failed", u.ID, "wrong password")
			writeErr(w, http.StatusForbidden, "the password is not right")
		} else {
			h.fail(w, err)
		}
		return key, false
	}
	return key, true
}

func (h *Handler) totpSetup(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if _, ok := h.confirmPassword(w, r, u, req.Password); !ok {
		return
	}
	secret := totp.NewSecret()
	if err := h.c.State.SetTOTPPending(r.Context(), u.ID, secret); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "two-factor login is already on")
			return
		}
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "account.totp.setup", u.ID, "secret generated, not yet on")
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "uri": totp.URI(totpIssuer, u.Username, secret)})
}

func (h *Handler) totpEnable(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	key := h.clientIP(r) + "|" + strings.ToLower(u.Username)
	if !h.limiter.allow(key) {
		writeErr(w, http.StatusTooManyRequests, tooManyAttempts)
		return
	}
	st, err := h.c.State.GetTOTP(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	if st.Enabled {
		writeErr(w, http.StatusConflict, "two-factor login is already on")
		return
	}
	if st.Secret == "" {
		writeErr(w, http.StatusBadRequest, "start the setup first")
		return
	}
	step, good := totp.Verify(st.Secret, req.Code, time.Now(), 0)
	if !good {
		h.limiter.fail(key)
		h.c.Audit(r.Context(), u.Username, "account.totp.failed", u.ID, "wrong code while turning on")
		writeErr(w, http.StatusForbidden, errBadCode)
		return
	}
	codes := store.NewRecoveryCodes(store.RecoveryCodeCount)
	if err := h.c.State.EnableTOTP(r.Context(), u.ID, store.HashRecoveryCodes(codes), step); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "two-factor login is already on")
			return
		}
		h.fail(w, err)
		return
	}
	h.limiter.reset(key)
	h.c.Audit(r.Context(), u.Username, "account.totp.enable", u.ID, "two-factor login turned on")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// passwordAndCode checks the password and a TOTP or recovery code of the signed-in user,
// for the actions that weaken or replace the second factor.
func (h *Handler) passwordAndCode(w http.ResponseWriter, r *http.Request, u *store.User, password, code string) bool {
	key, ok := h.confirmPassword(w, r, u, password)
	if !ok {
		return false
	}
	st, err := h.c.State.GetTOTP(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return false
	}
	if !st.Enabled {
		writeErr(w, http.StatusConflict, "two-factor login is not on")
		return false
	}
	good, _, _, err := h.checkSecondFactor(r.Context(), u.ID, st, code)
	if err != nil {
		h.fail(w, err)
		return false
	}
	if !good {
		h.limiter.fail(key)
		h.c.Audit(r.Context(), u.Username, "account.totp.failed", u.ID, "wrong code")
		writeErr(w, http.StatusForbidden, errBadCode)
		return false
	}
	return true
}

type passwordCode struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (h *Handler) totpDisable(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req passwordCode
	if !decode(w, r, &req) {
		return
	}
	if !h.passwordAndCode(w, r, u, req.Password, req.Code) {
		return
	}
	if err := h.c.State.DisableTOTP(r.Context(), u.ID); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "account.totp.disable", u.ID, "two-factor login turned off")
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

func (h *Handler) totpRecovery(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req passwordCode
	if !decode(w, r, &req) {
		return
	}
	if !h.passwordAndCode(w, r, u, req.Password, req.Code) {
		return
	}
	codes := store.NewRecoveryCodes(store.RecoveryCodeCount)
	if err := h.c.State.ReplaceRecovery(r.Context(), u.ID, store.HashRecoveryCodes(codes)); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "account.totp.recovery", u.ID, "recovery codes replaced")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// resetUserTOTP lets an admin turn two-factor off for another user who is locked out.
func (h *Handler) resetUserTOTP(w http.ResponseWriter, r *http.Request, u *store.User) {
	target, err := h.c.State.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	if err := h.c.State.DisableTOTP(r.Context(), target.ID); err != nil {
		h.fail(w, err)
		return
	}
	h.c.Audit(r.Context(), u.Username, "user.totp.reset", target.ID, "two-factor login turned off for "+target.Username)
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}
