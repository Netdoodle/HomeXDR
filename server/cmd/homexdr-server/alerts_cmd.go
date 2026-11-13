package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// alertsCmd changes alerts from the command line, for when the console is out of reach:
//
//	homexdr-server alerts resolve [-note "why"] <alert-id> ...
//
// Each change gets a note and an audit entry by "cli", like the console's.
func alertsCmd(args []string) int {
	if len(args) == 0 || args[0] != "resolve" {
		fmt.Fprintln(os.Stderr, `usage: homexdr-server alerts resolve [-note "why"] <alert-id> ...`)
		return 2
	}
	fs := flag.NewFlagSet("alerts resolve", flag.ContinueOnError)
	note := fs.String("note", "", "note added to each alert")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, `usage: homexdr-server alerts resolve [-note "why"] <alert-id> ...`)
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
	resolved := store.AlertResolved
	failed := 0
	for _, id := range fs.Args() {
		a, err := st.GetAlert(ctx, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", id, err)
			failed++
			continue
		}
		if strings.TrimSpace(*note) != "" {
			if _, err := st.AddAlertNote(ctx, id, "cli", *note); err != nil {
				fmt.Fprintf(os.Stderr, "%s: note: %v\n", id, err)
			}
		}
		if _, err := st.UpdateAlert(ctx, id, &resolved, nil); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", id, err)
			failed++
			continue
		}
		_ = st.Audit(ctx, "cli", "alert.update", id, "status resolved: "+*note)
		fmt.Printf("resolved %s (%s on %s)\n", id, a.Rule.Title, a.Hostname)
	}
	if failed > 0 {
		return 1
	}
	return 0
}
