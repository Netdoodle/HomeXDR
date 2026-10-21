package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestClaudeArgsLockDownTools(t *testing.T) {
	args := claudeArgs(config{model: "sonnet"}, "mcp.json")
	i := slices.Index(args, "--tools")
	if i < 0 || args[i+1] != "" {
		t.Fatalf("built-in tools not disabled: %q", args)
	}
	for _, want := range []string{"-p", "--strict-mcp-config", "dontAsk", "mcp__homexdr", "sonnet"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %q in %q", want, args)
		}
	}
}

// TestRunOnce runs the loop against a fake server with a fake "claude" that records its
// arguments and stdin.
func TestRunOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake claude is a shell script")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "record")
	fake := filepath.Join(dir, "claude")
	script := "#!/bin/sh\necho \"$@\" > " + record + "\ncat >> " + record + "\necho done\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var auth, runner string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, runner = r.Header.Get("Authorization"), r.Header.Get("X-HomeXDR-Runner")
		io.WriteString(w, `{"engine":"mcp","auto_trigger":true,"pending":2,"run":true,"ready":true}`)
	}))
	defer srv.Close()
	cfg := config{url: srv.URL, token: "hxm_test", claude: fake, name: "pc", interval: time.Second,
		timeout: time.Minute, perRun: 3, once: true}
	if err := run(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer hxm_test" || runner != "pc" {
		t.Fatalf("headers: %q %q", auth, runner)
	}
	b, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "--strict-mcp-config") || !strings.Contains(string(b), "next_investigation") ||
		!strings.Contains(string(b), "at most 3 alerts") {
		t.Fatalf("claude invocation: %s", b)
	}
}
