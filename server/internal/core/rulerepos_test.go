package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/config"
	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

func sigmaRule(id, title, level, status string) string {
	return fmt.Sprintf(`title: %s
id: %s
status: %s
level: %s
logsource: {category: process_creation, product: windows}
detection:
  sel:
    Image|endswith: '\%s.exe'
  condition: sel
`, title, id, status, level, strings.ReplaceAll(strings.ToLower(title), " ", ""))
}

// fakeGitHost serves one repository, /team/rules, whose default branch can be moved to
// another commit. Archives use the Gitea layout.
type fakeGitHost struct {
	*httptest.Server
	mu       sync.Mutex
	head     string
	commits  map[string]map[string]string // commit → path → content
	refsFail bool
	archives int
}

func newFakeGitHost(t *testing.T) *fakeGitHost {
	h := &fakeGitHost{commits: map[string]map[string]string{}}
	h.Server = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.Close)
	return h
}

func (h *fakeGitHost) push(commit string, files map[string]string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.commits[commit], h.head = files, commit
}

func (h *fakeGitHost) serve(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pkt := func(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }
	switch {
	case r.URL.Path == "/team/rules.git/info/refs":
		if h.refsFail {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		fmt.Fprint(w, pkt("# service=git-upload-pack\n")+"0000"+pkt(h.head+" HEAD\x00caps\n")+pkt(h.head+" refs/heads/main\n")+"0000")
	case strings.HasPrefix(r.URL.Path, "/team/rules/archive/"):
		commit := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/team/rules/archive/"), ".tar.gz")
		files, ok := h.commits[commit]
		if !ok {
			http.NotFound(w, r)
			return
		}
		h.archives++
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for name, body := range files {
			tw.WriteHeader(&tar.Header{Name: "rules-" + commit[:7] + "/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
			tw.Write([]byte(body))
		}
		tw.Close()
		gz.Close()
		w.Write(buf.Bytes())
	default:
		http.NotFound(w, r)
	}
}

func newRepoTestCore(t *testing.T) *Core {
	t.Helper()
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	os.MkdirAll(rulesDir, 0o755)
	os.WriteFile(filepath.Join(rulesDir, "b.yml"), []byte(sigmaRule("00000000-0000-4000-8000-00000000000b", "Builtin", "high", "stable")), 0o644)
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ev, err := events.OpenSQLite(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ev.Close() })
	cfg := config.Config{DataDir: dir, RulesDir: rulesDir}
	c, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitIdle(t *testing.T, c *Core, id string) *RuleRepoView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		v, err := c.RuleRepos.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if !v.Syncing {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatal("repository update did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func repoRuleTitles(t *testing.T, c *Core, repoID string) map[string]bool {
	t.Helper()
	rules, err := c.Rules.List(context.Background(), RuleFilter{Repo: repoID})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range rules {
		out[r.Title] = r.Enabled
	}
	return out
}

func TestRuleRepositories(t *testing.T) {
	ctx := context.Background()
	c := newRepoTestCore(t)
	host := newFakeGitHost(t)
	const (
		c1 = "1111111111111111111111111111111111111111"
		c2 = "2222222222222222222222222222222222222222"
		c3 = "3333333333333333333333333333333333333333"
	)
	v1 := map[string]string{
		"rules/windows/a.yml":    sigmaRule("00000000-0000-4000-8000-00000000000a", "Alpha", "high", "test"),
		"rules/windows/low.yml":  sigmaRule("00000000-0000-4000-8000-000000000001", "Lowly", "low", "test"),
		"rules/linux/old.yml":    sigmaRule("00000000-0000-4000-8000-000000000002", "Oldie", "high", "deprecated"),
		"rules/windows/dupe.yml": sigmaRule("00000000-0000-4000-8000-00000000000b", "Copy of builtin", "high", "test"),
		"rules/windows/bad.yml":  "title: Broken\nid: x\ndetection: {condition: nope}\n",
		"other/o.yml":            sigmaRule("00000000-0000-4000-8000-00000000000f", "Outside", "high", "test"),
	}
	host.push(c1, v1)

	// A URL into a folder fills in the branch and folder.
	v, err := c.RuleRepos.Add(ctx, store.RuleRepoSettings{
		URL: host.URL + "/team/rules/src/branch/main/rules", MinLevel: "medium", EnableRules: true, Enabled: true,
	}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if v.Ref != "main" || len(v.Paths) != 1 || v.Paths[0] != "rules" || v.Name != "team/rules" || v.IntervalHours != 24 {
		t.Fatalf("normalized settings = %+v", v.RuleRepoSettings)
	}
	id := v.ID
	v = waitIdle(t, c, id)
	if v.Version != c1 || v.Error != "" || v.Files != 6 || v.Added != 1 {
		t.Fatalf("after import: %+v", v.RuleRepoState)
	}
	if v.Rules != 1 || v.Filtered != 2 || v.Duplicates != 1 || v.RepoRuleStats.Errors != 1 || v.RulesEnabled != 1 {
		t.Fatalf("stats = %+v", v.RepoRuleStats)
	}
	if got := repoRuleTitles(t, c, id); len(got) != 1 || !got["Alpha"] {
		t.Fatalf("repo rules = %v", got)
	}
	if b, _ := c.Rules.Get(ctx, "00000000-0000-4000-8000-00000000000b"); b.Source != SourceBuiltin {
		t.Errorf("the rules folder must win over a repository: %+v", b)
	}
	a, _ := c.Rules.Get(ctx, "00000000-0000-4000-8000-00000000000a")
	if a.Source != SourceRepo || a.Repo == nil || a.Repo.Path != "rules/windows/a.yml" || a.Repo.URL != host.URL+"/team/rules/src/commit/"+c1+"/rules/windows/a.yml" {
		t.Errorf("repo rule = %+v %+v", a, a.Repo)
	}
	if _, err := c.Rules.SetEnabled(ctx, a.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Rules.SaveCustom(ctx, "", a.YAML); err == nil || !strings.Contains(err.Error(), "team/rules") {
		t.Errorf("saving a custom rule with a repository rule's id: %v", err)
	}

	// Manual updates: a check reports the new version but installs nothing.
	v2 := map[string]string{}
	for k, s := range v1 {
		v2[k] = s
	}
	v2["rules/windows/a.yml"] = sigmaRule("00000000-0000-4000-8000-00000000000a", "Alpha two", "high", "test")
	v2["rules/windows/new.yml"] = sigmaRule("00000000-0000-4000-8000-00000000000e", "Newbie", "critical", "test")
	host.push(c2, v2)
	if v, err = c.RuleRepos.Check(ctx, id, "admin"); err != nil {
		t.Fatal(err)
	}
	if !v.UpdateAvailable || v.LatestVersion != c2 || v.Version != c1 {
		t.Fatalf("after check: %+v", v.RuleRepoState)
	}
	// The schedule does the same for a manual repository whose interval has passed.
	st := v.RuleRepoState
	old := time.Now().Add(-25 * time.Hour)
	st.CheckedAt, st.LatestVersion = &old, ""
	c.State.UpdateRuleRepoState(ctx, id, st)
	c.RuleRepos.runDue(ctx)
	if v, _ = c.RuleRepos.Get(ctx, id); v.Version != c1 || v.LatestVersion != c2 {
		t.Fatalf("scheduled check of a manual repository: %+v", v.RuleRepoState)
	}
	if got := repoRuleTitles(t, c, id); len(got) != 1 || got["Alpha"] {
		t.Fatalf("rules changed before installing: %v", got)
	}
	// Installing it keeps the admin's choice for Alpha; the new rule follows the default.
	if !c.RuleRepos.Start(id, true, "admin") {
		t.Fatal("Start refused")
	}
	v = waitIdle(t, c, id)
	if v.Version != c2 || v.UpdateAvailable || v.Added != 1 || v.Removed != 0 {
		t.Fatalf("after manual update: %+v", v.RuleRepoState)
	}
	if got := repoRuleTitles(t, c, id); len(got) != 2 || got["Alpha two"] || !got["Newbie"] {
		t.Fatalf("after manual update: %v", got)
	}

	// Automatic updates install on schedule.
	set := v.RuleRepoSettings
	set.AutoUpdate = true
	if _, err := c.RuleRepos.Update(ctx, id, set, "admin"); err != nil {
		t.Fatal(err)
	}
	v3 := map[string]string{}
	for k, s := range v2 {
		v3[k] = s
	}
	delete(v3, "rules/windows/new.yml")
	host.push(c3, v3)
	c.RuleRepos.runDue(ctx) // not due yet
	if v, _ = c.RuleRepos.Get(ctx, id); v.Version != c2 {
		t.Fatalf("updated before the interval passed: %+v", v.RuleRepoState)
	}
	st = v.RuleRepoState
	st.CheckedAt = &old
	c.State.UpdateRuleRepoState(ctx, id, st)
	c.RuleRepos.runDue(ctx)
	if v, _ = c.RuleRepos.Get(ctx, id); v.Version != c3 || v.Removed != 1 {
		t.Fatalf("scheduled automatic update: %+v", v.RuleRepoState)
	}

	// Folder and filter changes reload what is on disk without downloading.
	downloads := host.archives
	set = v.RuleRepoSettings
	set.Paths, set.MinLevel = nil, ""
	if v, err = c.RuleRepos.Update(ctx, id, set, "admin"); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, c, id)
	if got := repoRuleTitles(t, c, id); len(got) != 3 || !got["Outside"] || !got["Lowly"] || host.archives != downloads {
		t.Fatalf("after widening folders: %v (downloads %d → %d)", got, downloads, host.archives)
	}

	// A failed check is recorded and leaves the installed rules alone.
	host.mu.Lock()
	host.refsFail = true
	host.mu.Unlock()
	if v, err = c.RuleRepos.Check(ctx, id, "admin"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.Error, "not found") || v.Rules != 3 {
		t.Fatalf("failed check: %+v", v.RuleRepoState)
	}
	if next := c.RuleRepos.nextCheck(v.RuleRepo); next.Sub(*v.CheckedAt) != repoRetry {
		t.Errorf("a failure should be retried within an hour, next check %v", next)
	}

	// Duplicate repositories are refused.
	if _, err := c.RuleRepos.Add(ctx, store.RuleRepoSettings{URL: host.URL + "/team/rules", Ref: "main", Enabled: true}, "admin"); err == nil {
		t.Error("adding the same repository and branch twice should fail")
	}

	// Disabling unloads the rules; removing deletes the files.
	set = v.RuleRepoSettings
	set.Enabled = false
	c.RuleRepos.Update(ctx, id, set, "admin")
	if got := repoRuleTitles(t, c, id); len(got) != 0 {
		t.Fatalf("disabled repository still loads %v", got)
	}
	if err := c.RuleRepos.Delete(ctx, id, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.RepoDir(id)); err == nil {
		t.Error("files left after removing the repository")
	}
	if left, _ := os.ReadDir(filepath.Dir(c.RepoDir(id))); len(left) != 0 {
		t.Errorf("leftovers in rule-repos: %v", left)
	}
	if _, err := c.RuleRepos.Get(ctx, id); err != store.ErrNotFound {
		t.Errorf("Get after delete: %v", err)
	}
}
