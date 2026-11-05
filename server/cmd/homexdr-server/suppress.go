package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// suppressApply creates the suppressions listed in a JSON file and closes the open alerts
// they match. It is safe to run while the server runs: the database is in WAL mode and the
// alerts are closed in small transactions. The server picks up new suppressions within 30
// seconds.
func suppressApply(args []string) int {
	fs := flag.NewFlagSet("suppress-apply", flag.ContinueOnError)
	file := fs.String("file", "", "JSON file listing the suppressions, in the same shape as POST /api/suppressions")
	dryRun := fs.Bool("dry-run", false, "print the counts and change nothing")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *file == "" {
		fmt.Fprintln(os.Stderr, "usage: homexdr-server suppress-apply --file spec.json [--dry-run]")
		return 2
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	specs, err := core.ParseSuppressionFile(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", *file, err)
		return 1
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
	res, err := core.ApplySuppressionSpecs(context.Background(), st, specs, "cli", *dryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	printSuppressionResult(res, *dryRun)
	return 0
}

func printSuppressionResult(res *core.SuppressionFileResult, dryRun bool) {
	for i, e := range res.Entries {
		what := "new"
		if e.Existing {
			what = "already exists"
		}
		fmt.Printf("%d. %s (%s)\n", i+1, e.Spec.Reason, what)
		if dryRun {
			fmt.Printf("   would close %d open alerts, %d kept for must-alert\n", e.Matches, e.Kept)
		} else {
			fmt.Printf("   closed %d open alerts, %d kept for must-alert\n", e.Closed, e.Kept)
		}
	}
	if dryRun {
		fmt.Printf("dry run: would create %d suppressions and close %d open alerts; nothing changed\n", res.Created, res.Matches)
		return
	}
	fmt.Printf("created %d suppressions, closed %d open alerts\n", res.Created, res.Closed)
}
