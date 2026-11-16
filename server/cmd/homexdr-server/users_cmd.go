package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// usersCmd handles `homexdr-server users ...`. For now: reset-2fa <username>, which turns
// two-factor login off for a user who lost their authenticator and recovery codes:
//
//	docker compose exec homexdr homexdr-server users reset-2fa admin
func usersCmd(args []string) int {
	if len(args) != 2 || args[0] != "reset-2fa" {
		fmt.Fprintln(os.Stderr, "usage: homexdr-server users reset-2fa <username>")
		return 2
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer st.Close()
	ctx := context.Background()
	users, err := st.ListUsers(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, u := range users {
		if !strings.EqualFold(u.Username, args[1]) {
			continue
		}
		if !u.TOTPEnabled {
			fmt.Println("two-factor login was already off for", u.Username)
			return 0
		}
		if err := st.DisableTOTP(ctx, u.ID); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		_ = st.Audit(ctx, "cli", "user.totp.reset", u.ID, "two-factor login turned off for "+u.Username)
		fmt.Println("two-factor login turned off for", u.Username, "(authenticator secret and recovery codes removed)")
		return 0
	}
	fmt.Fprintln(os.Stderr, "no such user")
	return 1
}
