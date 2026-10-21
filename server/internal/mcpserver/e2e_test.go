//go:build e2e

package mcpserver

// An end-to-end check with the real Claude Code: the runner starts "claude -p", which
// claims the queued alert over MCP and submits a report. It uses the Claude plan Claude
// Code is signed in with, so it only runs with -tags e2e:
//
//	go test -tags e2e -run TestClaudeCodeEndToEnd -v ./internal/mcpserver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/server/internal/triage"
)

func TestClaudeCodeEndToEnd(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.settings(t, func(s *triage.Settings) {
		s.MCPEnabled, s.Engine, s.MCPAutoTrigger = true, store.EngineMCP, true
	})
	f.tr.AlertCreated(ctx, f.alert)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(f.token), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", "../../cmd/homexdr-mcp-runner",
		"-url", f.srv.URL, "-token-file", tokenFile, "-once", "-per-run", "1", "-name", "e2e", "-model", "sonnet", "-timeout", "15m")
	out, err := cmd.CombinedOutput()
	t.Logf("runner output:\n%s", out)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		tr, err := f.st.GetTriage(ctx, f.alert.ID)
		if err == nil && tr.Status == store.TriageDone {
			t.Logf("verdict %s (%s) by %s, %d tool calls\nreport: %s", tr.Verdict, tr.Confidence, tr.Model, tr.ToolCalls, tr.Report)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no report: %+v %v", tr, err)
		}
		time.Sleep(time.Second)
	}
}
