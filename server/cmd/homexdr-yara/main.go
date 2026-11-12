// Command homexdr-yara is the YARA scanner the antivirus uses next to ClamAV (see
// internal/yarasvc and docs/antivirus.md). It runs in its own container, built from
// deploy/yara/Dockerfile, which provides the yara and yarac tools.
//
// Environment:
//
//	YARA_ADDR          listen address (default :3320)
//	YARA_DATA_DIR      downloaded and compiled rules (default /var/lib/homexdr-yara)
//	YARA_CUSTOM_DIR    your own *.yar / *.yara rules (default /rules)
//	YARA_FORGE_URL     rule package to download; "off" for custom rules only
//	                   (default: YARA Forge core)
//	YARA_UPDATE_HOURS  how often to check for a new package (default 24)
//	YARA_MAX_MB        largest file accepted (default 100)
//	YARA_PARALLEL      concurrent scans (default 2)
//
// "homexdr-yara healthcheck" exits 0 when the service answers with rules loaded.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/yarasvc"
)

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if n, err := strconv.Atoi(env(k, "")); err == nil && n > 0 {
		return n
	}
	return def
}

func main() {
	addr := env("YARA_ADDR", ":3320")
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		host := addr
		if strings.HasPrefix(host, ":") {
			host = "127.0.0.1" + host
		}
		c := http.Client{Timeout: 4 * time.Second}
		resp, err := c.Get("http://" + host + "/healthz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	forge := env("YARA_FORGE_URL", yarasvc.DefaultForgeURL)
	if strings.EqualFold(forge, "off") {
		forge = ""
	}
	cfg := yarasvc.Config{
		Addr:        addr,
		DataDir:     env("YARA_DATA_DIR", "/var/lib/homexdr-yara"),
		CustomDir:   env("YARA_CUSTOM_DIR", "/rules"),
		ForgeURL:    forge,
		UpdateEvery: time.Duration(envInt("YARA_UPDATE_HOURS", 24)) * time.Hour,
		MaxBytes:    int64(envInt("YARA_MAX_MB", 100)) << 20,
		Parallel:    envInt("YARA_PARALLEL", 2),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	svc := yarasvc.New(cfg, log)
	if err := svc.Start(ctx); err != nil {
		log.Error("start", "err", err)
		os.Exit(1)
	}
	srv := &http.Server{Addr: cfg.Addr, Handler: svc.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Info("homexdr-yara listening", "addr", cfg.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}
