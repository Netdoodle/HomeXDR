package console

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/totp"
)

// removeHost permanently deletes a host. It is the one host action that cannot be undone,
// so besides the admin role it needs the hostname typed back and a fresh authenticator
// code from the signed-in admin (a recovery code does not count). Wrong codes are counted
// like wrong codes at login, per address and per account together with login's count.
func (h *Handler) removeHost(w http.ResponseWriter, r *http.Request, u *store.User) {
	var req struct {
		TOTPCode        string `json:"totp_code"`
		ConfirmHostname string `json:"confirm_hostname"`
	}
	if !decode(w, r, &req) {
		return
	}
	host, err := h.c.State.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	st, err := h.c.State.GetTOTP(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	if !st.Enabled {
		writeErr(w, http.StatusForbidden, "set up two-factor authentication first (Account > Two-factor), then try again")
		return
	}
	if strings.TrimSpace(req.ConfirmHostname) == "" || !strings.EqualFold(strings.TrimSpace(req.ConfirmHostname), host.Hostname) {
		writeErr(w, http.StatusBadRequest, "type the host's name exactly to confirm")
		return
	}

	ip := h.clientIP(r)
	key := limitIP(ip) + "|mfa|" + u.ID
	acct := "mfa-account|" + u.ID
	if !h.limiter.take(key, loginMaxFails) {
		writeErr(w, http.StatusTooManyRequests, tooManyAttempts)
		return
	}
	if !h.limiter.take(acct, mfaAccountMaxFails) {
		h.limiter.success(key)
		writeErr(w, http.StatusTooManyRequests, tooManyAttempts)
		return
	}
	giveBack := func() {
		h.limiter.success(key)
		h.limiter.success(acct)
	}
	step, good := totp.Verify(st.Secret, req.TOTPCode, time.Now(), st.LastStep)
	if good {
		// Records the step; false means the same code was just used by another request.
		used, err := h.c.State.UseTOTPStep(r.Context(), u.ID, step)
		if err != nil {
			giveBack()
			h.fail(w, err)
			return
		}
		good = used
	}
	if !good {
		h.c.Audit(r.Context(), u.Username, "host.remove_failed", host.ID, "wrong authenticator code from "+ip)
		writeErr(w, http.StatusForbidden, errBadCode)
		return
	}
	h.limiter.reset(key)
	h.limiter.reset(acct)

	uploads, err := h.c.State.RemoveHost(r.Context(), host.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	for _, p := range uploads {
		_ = os.Remove(p)
	}
	h.c.Audit(r.Context(), u.Username, "host.remove", host.ID, host.Hostname+" ("+host.Kind+") removed with its commands and findings")
	w.WriteHeader(http.StatusNoContent)
}
