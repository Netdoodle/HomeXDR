// Command homexdr-server runs the HomeXDR server: agent API, console, syslog intake,
// detection and storage.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/agentapi"
	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/console"
	"github.com/Netdoodle/homexdr/server/internal/core"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/pki"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/syslog"
	"github.com/Netdoodle/homexdr/server/internal/webui"
	"github.com/Netdoodle/homexdr/shared/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println("homexdr-server", version.String())
			return
		case "healthcheck":
			os.Exit(healthcheck())
		case "reset-password":
			os.Exit(resetPassword(os.Args[2:]))
		case "enrollment-token":
			os.Exit(enrollmentToken(os.Args[2:]))
		case "release-manifest":
			os.Exit(releaseManifest(os.Args[2:]))
		case "serve":
		default:
			fmt.Fprintf(os.Stderr, "usage: homexdr-server [serve|version|healthcheck|reset-password|enrollment-token|release-manifest]\n")
			os.Exit(2)
		}
	}
	if err := serve(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	log.Info("starting homexdr-server", "version", version.String(), "data", cfg.DataDir, "event_store", cfg.EventStore)

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p, err := pki.Load(filepath.Join(cfg.DataDir, "pki"), cfg.ServerNames)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	var ev events.Store
	switch cfg.EventStore {
	case "clickhouse":
		ev, err = events.OpenClickHouse(ctx, cfg.ClickHouseDSN, cfg.RetentionDays)
	default:
		ev, err = events.OpenSQLite(filepath.Join(cfg.DataDir, "events.db"))
	}
	if err != nil {
		return err
	}
	defer ev.Close()

	c, err := core.New(ctx, cfg, log, st, ev, p)
	if err != nil {
		return err
	}

	// Console + REST API.
	consoleAPI := console.New(c)
	web := webui.Handler(cfg.WebDir)
	httpMux := http.NewServeMux()
	httpMux.Handle("/api/", consoleAPI)
	httpMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		status := map[string]string{"status": "ok", "event_store": "ok", "state_store": "ok"}
		code := http.StatusOK
		hctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := ev.Ping(hctx); err != nil {
			status["event_store"], status["status"], code = "error: "+err.Error(), "degraded", http.StatusServiceUnavailable
		}
		if err := st.Ping(hctx); err != nil {
			status["state_store"], status["status"], code = "error: "+err.Error(), "degraded", http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"status":%q,"event_store":%q,"state_store":%q}`+"\n", status["status"], status["event_store"], status["state_store"])
	})
	httpMux.Handle("/", web)
	httpSrv := &http.Server{
		Addr: cfg.HTTPAddr, Handler: httpMux,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	// Agent API (TLS). WriteTimeout must exceed the long-poll wait.
	agentSrv := &http.Server{
		Addr: cfg.AgentAddr, Handler: agentapi.New(c), TLSConfig: p.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 5 * time.Minute,
		IdleTimeout:  2 * time.Minute,
		ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelDebug), // TLS handshake noise
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}

	var wg sync.WaitGroup
	errc := make(chan error, 3)
	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	run("console", func() error {
		log.Info("console listening", "addr", cfg.HTTPAddr)
		return httpSrv.ListenAndServe()
	})
	run("agent api", func() error {
		log.Info("agent api listening", "addr", cfg.AgentAddr, "agent_url", cfg.AgentURL, "ca_pin", p.CAPin())
		return agentSrv.ListenAndServeTLS("", "")
	})
	if cfg.SyslogAddr != "" {
		lis := syslog.New(c, cfg.SyslogAllow)
		run("syslog", func() error { return lis.Run(ctx, cfg.SyslogAddr) })
	}
	go c.RunMaintenance(ctx)

	if n, _ := st.CountUsers(ctx); n == 0 {
		log.Info("no users yet: open the console to create the admin account", "addr", cfg.HTTPAddr)
	}

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case runErr = <-errc:
		log.Error("listener failed", "err", runErr)
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	_ = agentSrv.Shutdown(shutdownCtx)
	wg.Wait()
	return runErr
}

// healthcheck is used by the container HEALTHCHECK (the image has no curl).
func healthcheck() int {
	addr := os.Getenv("HOMEXDR_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy:", resp.Status)
		return 1
	}
	return 0
}

// resetPassword sets a console user's password from HOMEXDR_NEW_PASSWORD, for recovery
// when nobody can log in: docker compose exec -e HOMEXDR_NEW_PASSWORD=... homexdr homexdr-server reset-password admin
func resetPassword(args []string) int {
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: HOMEXDR_NEW_PASSWORD=... homexdr-server reset-password <username>")
		return 2
	}
	pw := os.Getenv("HOMEXDR_NEW_PASSWORD")
	if pw == "" {
		fmt.Fprintln(os.Stderr, "set HOMEXDR_NEW_PASSWORD")
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
		if strings.EqualFold(u.Username, fs.Arg(0)) {
			if _, err := st.UpdateUser(ctx, u.ID, "", pw); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			_ = st.Audit(ctx, "cli", "user.reset_password", u.ID, u.Username)
			fmt.Println("password updated for", u.Username)
			return 0
		}
	}
	fmt.Fprintln(os.Stderr, "no such user")
	return 1
}

// enrollmentToken creates an enrollment token from the command line, for scripted agent
// installs on the server's own host:
//
//	docker exec homexdr homexdr-server enrollment-token --name tower --max-uses 1 --expires-hours 1
//
// It prints only the token. Running it needs access to the container, which already
// implies full control of the server.
func enrollmentToken(args []string) int {
	fs := flag.NewFlagSet("enrollment-token", flag.ContinueOnError)
	name := fs.String("name", "cli", "token name shown in the console")
	hours := fs.Int("expires-hours", 24, "hours until the token expires (0 = never)")
	uses := fs.Int("max-uses", 1, "how many enrollments the token allows (0 = unlimited)")
	labels := fs.String("labels", "", "comma-separated labels for hosts enrolled with it")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
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
	var exp *time.Time
	if *hours > 0 {
		t := time.Now().Add(time.Duration(*hours) * time.Hour).UTC()
		exp = &t
	}
	var maxUses *int
	if *uses > 0 {
		maxUses = uses
	}
	var ls []string
	for _, l := range strings.Split(*labels, ",") {
		if l = strings.ToLower(strings.TrimSpace(l)); l != "" {
			ls = append(ls, l)
		}
	}
	ctx := context.Background()
	tok, err := st.CreateToken(ctx, *name, "cli", exp, maxUses, ls)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = st.Audit(ctx, "cli", "token.create", tok.ID, tok.Name)
	fmt.Println(tok.Token)
	return 0
}

// releaseManifest writes the agent release manifest for the binaries in a directory,
// stamped with this binary's version metadata (the image build runs it right after
// building the agents with the same -ldflags).
func releaseManifest(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: homexdr-server release-manifest <downloads dir>")
		return 2
	}
	rel, err := core.WriteManifest(args[0], version.Version, version.Commit, version.CommitUnix())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("wrote %s/agent-release.json: %s, %d binaries\n", args[0], rel.Version, len(rel.Files))
	return 0
}
