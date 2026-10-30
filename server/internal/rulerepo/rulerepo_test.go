package rulerepo

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in                         string
		kind, url, host, ref, path string
		name                       string
	}{
		{in: "https://github.com/SigmaHQ/sigma", kind: KindGit, url: "https://github.com/SigmaHQ/sigma", host: HostGitHub, name: "SigmaHQ/sigma"},
		{in: "SigmaHQ/sigma", kind: KindGit, url: "https://github.com/SigmaHQ/sigma", host: HostGitHub, name: "SigmaHQ/sigma"},
		{in: "github.com/SigmaHQ/sigma.git", kind: KindGit, url: "https://github.com/SigmaHQ/sigma", host: HostGitHub},
		{in: "https://github.com/SigmaHQ/sigma/tree/master/rules/windows/", kind: KindGit, url: "https://github.com/SigmaHQ/sigma", host: HostGitHub, ref: "master", path: "rules/windows"},
		{in: "https://gitlab.com/grp/sub/rules/-/tree/main/linux", kind: KindGit, url: "https://gitlab.com/grp/sub/rules", host: HostGitLab, ref: "main", path: "linux", name: "sub/rules"},
		{in: "https://codeberg.org/me/detections/src/branch/dev/rules", kind: KindGit, url: "https://codeberg.org/me/detections", host: HostGitea, ref: "dev", path: "rules"},
		{in: "https://bitbucket.org/team/repo/src/main/x", kind: KindGit, url: "https://bitbucket.org/team/repo", host: HostBitbucket, ref: "main", path: "x"},
		{in: "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip", kind: KindArchive,
			url: "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip", name: "sigma_core"},
		{in: "http://nas.lan:8000/rules.tar.gz", kind: KindArchive, url: "http://nas.lan:8000/rules.tar.gz", name: "rules"},
	}
	for _, c := range cases {
		s, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if s.Kind != c.kind || s.URL != c.url || s.Host != c.host || s.Ref != c.ref || s.Path != c.path {
			t.Errorf("Parse(%q) = %+v", c.in, s)
		}
		if c.name != "" && s.Name() != c.name {
			t.Errorf("Parse(%q).Name() = %q, want %q", c.in, s.Name(), c.name)
		}
	}
	for _, bad := range []string{"", "ftp://example.com/x/y", "https://user:pw@github.com/a/b", "https://github.com/onlyowner", "https://gitlab.com/x"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
}

func TestFolders(t *testing.T) {
	if f, err := CleanFolder(" /rules/windows/ "); err != nil || f != "rules/windows" {
		t.Errorf("CleanFolder = %q, %v", f, err)
	}
	if _, err := CleanFolder("../etc"); err == nil {
		t.Error("CleanFolder should reject ../")
	}
	if !InFolders("rules/windows/a.yml", []string{"rules/windows"}) || InFolders("rules/windows2/a.yml", []string{"rules/windows"}) ||
		!InFolders("x.yml", nil) {
		t.Error("InFolders")
	}
	src, _ := Parse("https://github.com/SigmaHQ/sigma")
	if got := src.FileURL("abc", "rules/x.yml"); got != "https://github.com/SigmaHQ/sigma/blob/abc/rules/x.yml" {
		t.Errorf("FileURL = %q", got)
	}
}

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

const (
	headCommit = "1111111111111111111111111111111111111111"
	devCommit  = "2222222222222222222222222222222222222222"
	tagObject  = "3333333333333333333333333333333333333333"
	tagCommit  = "4444444444444444444444444444444444444444"
)

func advertisement() string {
	return pkt("# service=git-upload-pack\n") + "0000" +
		pkt(headCommit+" HEAD\x00multi_ack symref=HEAD:refs/heads/main\n") +
		pkt(headCommit+" refs/heads/main\n") +
		pkt(devCommit+" refs/heads/dev\n") +
		pkt(tagObject+" refs/tags/v1\n") +
		pkt(tagCommit+" refs/tags/v1^{}\n") + "0000"
}

func tarGz(t *testing.T, files map[string]string, extra func(tw *tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	if extra != nil {
		extra(tw)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// gitServer serves a fake repository at /owner/repo with Gitea-style archives (or
// GitLab-style when gitlab is set, to exercise the fallback).
func gitServer(t *testing.T, gitlab bool, archive []byte) (*httptest.Server, *[]string) {
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch {
		case r.URL.Path == "/owner/repo.git/info/refs" && r.URL.Query().Get("service") == "git-upload-pack":
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			fmt.Fprint(w, advertisement())
		case !gitlab && strings.HasPrefix(r.URL.Path, "/owner/repo/archive/"):
			w.Write(archive)
		case gitlab && strings.HasPrefix(r.URL.Path, "/owner/repo/-/archive/"):
			w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestResolve(t *testing.T) {
	srv, _ := gitServer(t, false, nil)
	src, err := Parse(srv.URL + "/owner/repo")
	if err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{}
	ctx := context.Background()
	for ref, want := range map[string]string{"": headCommit, "main": headCommit, "dev": devCommit, "v1": tagCommit, "refs/heads/dev": devCommit, devCommit: devCommit} {
		got, err := f.Latest(ctx, src, ref, Remote{})
		if err != nil || got.Version != want {
			t.Errorf("Latest(%q) = %q, %v; want %q", ref, got.Version, err, want)
		}
	}
	if _, err := f.Latest(ctx, src, "nope", Remote{}); err == nil || !strings.Contains(err.Error(), `no branch or tag named "nope"`) {
		t.Errorf("unknown ref: %v", err)
	}
	missing, _ := Parse(srv.URL + "/owner/missing")
	if _, err := f.Latest(ctx, missing, "", Remote{}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing repo: %v", err)
	}
}

func TestFetchGit(t *testing.T) {
	archive := tarGz(t, map[string]string{
		"repo-1111/rules/windows/a.yml":     "title: a",
		"repo-1111/rules/linux/b.yaml":      "title: b",
		"repo-1111/README.md":               "readme",
		"repo-1111/.github/workflows/c.yml": "ci",
		"repo-1111/../escape.yml":           "nope",
		"top.yml":                           "no top folder",
	}, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: "repo-1111/rules/link.yml", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
		big := strings.Repeat("x", MaxFileSize+1)
		tw.WriteHeader(&tar.Header{Name: "repo-1111/rules/big.yml", Mode: 0o644, Size: int64(len(big)), Typeflag: tar.TypeReg})
		tw.Write([]byte(big))
	})
	for _, gitlab := range []bool{false, true} {
		srv, hits := gitServer(t, gitlab, archive)
		src, _ := Parse(srv.URL + "/owner/repo")
		work := t.TempDir()
		dir := filepath.Join(work, "repo")
		f := &Fetcher{}
		rem, st, changed, err := f.Fetch(context.Background(), src, "", Remote{}, dir)
		if err != nil || !changed || rem.Version != headCommit {
			t.Fatalf("gitlab=%v: Fetch = %+v changed=%v err=%v (hits %v)", gitlab, rem, changed, err, *hits)
		}
		if st.Files != 2 || st.Skipped != 1 {
			t.Errorf("stats = %+v", st)
		}
		for _, want := range []string{"rules/windows/a.yml", "rules/linux/b.yaml"} {
			if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
				t.Errorf("missing %s", want)
			}
		}
		for _, unwanted := range []string{"README.md", ".github", "rules/link.yml", "rules/big.yml", "top.yml"} {
			if _, err := os.Lstat(filepath.Join(dir, unwanted)); err == nil {
				t.Errorf("%s should not be extracted", unwanted)
			}
		}
		if _, err := os.Stat(filepath.Join(work, "escape.yml")); err == nil {
			t.Error("path traversal escaped the folder")
		}
		if got := Folders(dir); len(got) != 3 || got[0] != (Folder{"rules", 2}) {
			t.Errorf("Folders = %+v", got)
		}
		// Same commit again: nothing to download.
		n := len(*hits)
		_, _, changed, err = f.Fetch(context.Background(), src, "", rem, filepath.Join(work, "again"))
		if err != nil || changed || len(*hits) != n+1 {
			t.Errorf("unchanged fetch: changed=%v err=%v hits=%v", changed, err, (*hits)[n:])
		}
		left, _ := os.ReadDir(work)
		if len(left) != 1 {
			t.Errorf("temporary files left behind: %v", left)
		}
	}
}

func TestFetchArchive(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("rules/windows/a.yml")
	w.Write([]byte("title: a"))
	zw.Close()
	body := zbuf.Bytes()
	gets := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write(body)
	}))
	defer srv.Close()
	src, err := Parse(srv.URL + "/sigma_core.zip")
	if err != nil || src.Kind != KindArchive {
		t.Fatalf("Parse: %+v %v", src, err)
	}
	f := &Fetcher{}
	work := t.TempDir()
	rem, st, changed, err := f.Fetch(context.Background(), src, "", Remote{}, filepath.Join(work, "a"))
	if err != nil || !changed || st.Files != 1 || !strings.HasPrefix(rem.Version, "sha256:") || rem.ETag != `"v1"` {
		t.Fatalf("Fetch = %+v %+v %v %v", rem, st, changed, err)
	}
	// The zip's own top-level folder is kept (no stripping for plain archives).
	if _, err := os.Stat(filepath.Join(work, "a", "rules", "windows", "a.yml")); err != nil {
		t.Error(err)
	}
	latest, err := f.Latest(context.Background(), src, "", rem)
	if err != nil || latest != rem {
		t.Errorf("Latest with ETag = %+v %v", latest, err)
	}
	// Without validators the content hash decides.
	_, _, changed, err = f.Fetch(context.Background(), src, "", Remote{Version: rem.Version}, filepath.Join(work, "b"))
	if err != nil || changed {
		t.Errorf("same content: changed=%v err=%v", changed, err)
	}
	if gets != 3 {
		t.Errorf("gets = %d", gets)
	}
	notArchive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html>") }))
	defer notArchive.Close()
	bad, _ := Parse(notArchive.URL + "/x.zip")
	if _, _, _, err := f.Fetch(context.Background(), bad, "", Remote{}, filepath.Join(work, "c")); err == nil {
		t.Error("an HTML page should not extract")
	}
	if _, err := os.Stat(filepath.Join(work, "c")); err == nil {
		t.Error("failed extraction left its folder behind")
	}
}
