package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// downStore stands in for an event store that cannot be reached, so the doctor can still
// report that and everything else. Only what the doctor and self-check call is overridden;
// they stop at Ping or at the type check in events.SourceActivity.
type downStore struct {
	events.Store
	err error
}

func (d downStore) Ping(context.Context) error          { return d.err }
func (d downStore) Size(context.Context) (int64, error) { return 0, d.err }
func (d downStore) Close() error                        { return nil }
func (d downStore) Search(context.Context, events.SearchQuery) (*events.SearchResult, error) {
	return nil, d.err
}

// openCore builds a Core for a command-line tool, sharing the running server's databases.
// Nothing runs in the background.
func openCore(ctx context.Context) (*core.Core, func(), error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.db"))
	if err != nil {
		return nil, nil, err
	}
	var ev events.Store
	switch cfg.EventStore {
	case "clickhouse":
		ev, err = events.OpenClickHouse(ctx, cfg.ClickHouseDSN, cfg.RetentionDays)
	default:
		ev, err = events.OpenSQLite(filepath.Join(cfg.DataDir, "events.db"))
	}
	if err != nil {
		ev = downStore{err: errors.New("could not connect to the event store")}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New(ctx, cfg, log, st, ev, nil)
	if err != nil {
		ev.Close()
		st.Close()
		return nil, nil, err
	}
	return c, func() { ev.Close(); st.Close() }, nil
}

var checkMark = map[string]string{core.CheckOK: "ok", core.CheckWarn: "warn", core.CheckFail: "FAIL", core.CheckSkip: "skip"}

// doctor prints every check, and exits 1 when one fails.
func doctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c, closeAll, err := openCore(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer closeAll()
	rep := c.RunDoctor(ctx)
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(rep)
	} else {
		for _, r := range rep.Results {
			fmt.Printf("[%-4s] %s: %s\n", checkMark[r.Status], r.Name, r.Message)
			if r.Fix != "" {
				fmt.Printf("       Fix: %s\n", r.Fix)
			}
		}
		fmt.Printf("\n%d ok, %d warnings, %d failed\n", rep.OK, rep.Warn, rep.Fail)
	}
	if rep.Fail > 0 {
		return 1
	}
	return 0
}

// selfcheck runs the self-check, and exits 1 on a regression or when the pipeline check fails.
func selfcheck(args []string) int {
	fs := flag.NewFlagSet("selfcheck", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	c, closeAll, err := openCore(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer closeAll()
	res := c.RunSelfCheck(ctx)
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(res)
	} else {
		printSelfCheck(res)
	}
	if res.Bad() {
		return 1
	}
	return 0
}

func printSelfCheck(res *core.SelfCheckResult) {
	fmt.Printf("Detection rate: %.1f%% (%d of %d enabled rules fired on an event built from their own selection)\n", res.Rate, res.Fired, res.Rules)
	if p := res.Previous; p != nil {
		fmt.Printf("Previous run:   %.1f%% (%d of %d) on %s\n", p.Rate, p.Fired, p.Rules, p.At.Format(time.RFC1123))
	}
	for i, f := range res.Failures {
		if i == 20 {
			fmt.Printf("  ... and %d more\n", res.Failed-i)
			break
		}
		fmt.Printf("  %s (%s): %s\n", f.Title, f.RuleID, f.Reason)
	}
	state := "FAILED"
	if res.Pipeline.Passed {
		state = "passed"
	}
	fmt.Printf("Pipeline check: %s. %s\n", state, res.Pipeline.Message)
	if cov := res.Coverage; cov != nil {
		if cov.Note != "" {
			fmt.Println("Field coverage:", cov.Note)
		}
		if cov.Events > 0 {
			fmt.Printf("Field coverage: %d of %d rules cannot fire on this install's data (%d events sampled from %d sources, last %d days)\n",
				cov.CannotFire, cov.Rules, cov.Events, cov.Sources, cov.Days)
			for i, g := range cov.Groups {
				if i == 15 {
					fmt.Printf("  ... and %d more logsources\n", len(cov.Groups)-i)
					break
				}
				var missing []string
				for _, f := range g.Missing {
					missing = append(missing, f.Field)
				}
				line := fmt.Sprintf("  %-40s %5d rules, %5d can fire, %5d no such events, %5d missing a field", g.Logsource, g.Rules, g.CanFire, g.NoEvents, g.MissingField)
				if len(missing) > 0 {
					line += " (" + strings.Join(missing, ", ") + ")"
				}
				fmt.Println(line)
			}
		}
	}
	if res.Regression {
		fmt.Println("REGRESSION:", res.Reason)
	} else if res.Reason != "" {
		fmt.Println(res.Reason)
	}
}
