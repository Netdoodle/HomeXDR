package console

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/totp"
)

func TestLimiterTakeIsAtomic(t *testing.T) {
	l := newLoginLimiter()
	var got atomic.Int32
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.take("k", loginMaxFails) {
				got.Add(1)
			}
		}()
	}
	wg.Wait()
	if got.Load() != loginMaxFails {
		t.Fatalf("%d parallel attempts got through, want %d", got.Load(), loginMaxFails)
	}
	// Attempts that passed give their slot back.
	l.success("k")
	if !l.take("k", loginMaxFails) || l.take("k", loginMaxFails) {
		t.Fatal("success did not give back exactly one attempt")
	}
	l.reset("k")
	if l.count("k") != 0 {
		t.Fatal("reset left attempts")
	}
}

func TestLimiterEvictsOldestKeys(t *testing.T) {
	l := newLoginLimiter()
	l.take("target", loginMaxFails)
	l.take("target", loginMaxFails)
	// Make every other key look older than the target.
	old := time.Now().Add(-time.Minute)
	l.mu.Lock()
	for i := range limiterMaxKeys {
		l.failures[fmt.Sprintf("spray-%d", i)] = []time.Time{old}
	}
	l.mu.Unlock()
	l.take("trigger", loginMaxFails)
	if n := len(l.failures); n > limiterMaxKeys/2 {
		t.Fatalf("%d keys left after eviction", n)
	}
	if l.count("target") != 2 || l.count("trigger") != 1 {
		t.Fatalf("eviction dropped recent keys: target %d trigger %d", l.count("target"), l.count("trigger"))
	}
}

func TestLimitIP(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":                  "192.0.2.7",
		"::ffff:192.0.2.7":           "192.0.2.7",
		"2001:db8:1:2:aaaa::1":       "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff::99": "2001:db8:1:2::/64",
		"fe80::1%eth0":               "fe80::/64",
		"not-an-ip":                  "not-an-ip",
	} {
		if got := limitIP(in); got != want {
			t.Errorf("limitIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParallelWrongPasswordsAreLimited(t *testing.T) {
	_, srv := setup(t)
	admin := newClient(t, srv)
	if code, _ := admin.do("POST", "/api/setup", map[string]string{"username": "admin", "password": adminPW}, true); code != 200 {
		t.Fatalf("setup = %d", code)
	}
	var wrong atomic.Int32
	var wg sync.WaitGroup
	for i := range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := admin.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": fmt.Sprintf("wrong password %d", i)}, true)
			if code == http.StatusUnauthorized {
				wrong.Add(1)
			}
		}()
	}
	wg.Wait()
	if wrong.Load() != loginMaxFails {
		t.Fatalf("%d wrong passwords were checked, want %d", wrong.Load(), loginMaxFails)
	}
	if code, _ := admin.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": adminPW}, true); code != http.StatusTooManyRequests {
		t.Fatalf("right password while limited = %d", code)
	}
}

func TestMFAAccountLimitAcrossAddresses(t *testing.T) {
	e := newMFAEnv(t)
	cl, tok := e.passwordStep(t, "admin", adminPW)
	u, err := e.h.c.State.Authenticate(context.Background(), "admin", adminPW)
	if err != nil {
		t.Fatal(err)
	}
	acct := "mfa-account|" + u.ID
	// Wrong codes from other addresses, as if from many machines.
	for range mfaAccountMaxFails - 1 {
		e.h.limiter.take(acct, mfaAccountMaxFails)
	}
	if c := e.mfa(cl, tok, "000000"); c != http.StatusUnauthorized && c != http.StatusOK {
		t.Fatalf("wrong code = %d", c)
	} else if c == http.StatusOK {
		t.Skip("000000 happened to be the right code")
	}
	// The account is now locked: even the right code from a fresh address is refused.
	cl2, tok2 := e.passwordStep(t, "admin", adminPW)
	if c := e.mfa(cl2, tok2, totp.Code(e.secret, time.Now())); c != http.StatusTooManyRequests {
		t.Fatalf("right code while the account is locked = %d", c)
	}
	alerts, _, err := e.h.c.State.ListAlerts(context.Background(), store.AlertFilter{HostID: core.ServerHostID})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range alerts {
		if a.Rule.ID == "auth:mfa-guessing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no two-factor guessing alert among %d server alerts", len(alerts))
	}
}
