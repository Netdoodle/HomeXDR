// Package rulerepo downloads Sigma rule collections for the server to load: a public git
// repository on GitHub, GitLab, Gitea/Forgejo (Codeberg) or Bitbucket, or a .zip /
// .tar.gz archive at any URL (such as a SigmaHQ release package).
//
// Git repositories are fetched without git: the newest commit of a branch or tag comes
// from the repository's smart-HTTP ref advertisement (what `git ls-remote` reads), and
// the files from the host's archive download for that commit. Only .yml/.yaml files are
// kept.
package rulerepo

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Source kinds.
const (
	KindGit     = "git"
	KindArchive = "archive"
)

// Git hosts, which decide the archive and browse URL layouts.
const (
	HostGitHub    = "github"
	HostGitLab    = "gitlab"
	HostBitbucket = "bitbucket"
	HostGitea     = "gitea" // also Forgejo, Codeberg and unrecognized hosts
)

// Source is a parsed repository or archive URL.
type Source struct {
	Kind string // KindGit or KindArchive
	// URL is the repository's web URL without ".git" or a trailing slash
	// (https://github.com/SigmaHQ/sigma), or the archive URL.
	URL  string
	Host string // git only: HostGitHub, HostGitLab, HostBitbucket or HostGitea
	// Ref and Path are set when the URL pointed into the repository, such as
	// https://github.com/SigmaHQ/sigma/tree/master/rules/windows.
	Ref  string
	Path string
}

var shortGitHub = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// Parse reads a repository or archive URL. Besides full URLs it accepts "owner/repo"
// (GitHub) and URLs without a scheme ("github.com/owner/repo").
func Parse(raw string) (Source, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Source{}, errors.New("enter a repository or archive URL")
	}
	if shortGitHub.MatchString(raw) && !strings.Contains(strings.SplitN(raw, "/", 2)[0], ".") {
		raw = "https://github.com/" + raw
	} else if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Source{}, fmt.Errorf("not a valid URL: %v", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return Source{}, fmt.Errorf("only http and https URLs are supported, not %s", u.Scheme)
	}
	if u.User != nil {
		return Source{}, errors.New("credentials in the URL are not supported; use a public repository or archive")
	}
	if u.Host == "" {
		return Source{}, errors.New("the URL has no host")
	}
	lower := strings.ToLower(u.Path)
	if strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		u.Fragment = ""
		return Source{Kind: KindArchive, URL: u.String()}, nil
	}

	segs := splitPath(u.Path)
	host := strings.ToLower(u.Hostname())
	src := Source{Kind: KindGit}
	var repo []string
	switch {
	case host == "github.com" || strings.Contains(host, "github"):
		src.Host = HostGitHub
		repo, src.Ref, src.Path = splitRepo(segs, 2, "tree", "blob")
	case strings.Contains(host, "gitlab"):
		// Nested groups: everything before the "/-/" separator is the project path.
		src.Host = HostGitLab
		repo = segs
		for i, s := range segs {
			if s == "-" {
				repo = segs[:i]
				if rest := segs[i+1:]; len(rest) >= 2 && (rest[0] == "tree" || rest[0] == "blob") {
					src.Ref, src.Path = rest[1], strings.Join(rest[2:], "/")
				}
				break
			}
		}
		if len(repo) < 2 {
			return Source{}, errors.New("expected a GitLab project URL such as https://gitlab.com/group/project")
		}
	case host == "bitbucket.org":
		src.Host = HostBitbucket
		repo, src.Ref, src.Path = splitRepo(segs, 2, "src")
	default:
		// Gitea and Forgejo: /owner/repo/src/branch/<ref>/<path>.
		src.Host = HostGitea
		repo = segs
		if len(segs) > 2 {
			repo = segs[:2]
			if rest := segs[2:]; len(rest) >= 3 && rest[0] == "src" {
				src.Ref, src.Path = rest[2], strings.Join(rest[3:], "/")
			}
		}
	}
	if len(repo) < 2 {
		return Source{}, errors.New("expected a repository URL such as https://github.com/SigmaHQ/sigma")
	}
	repo[len(repo)-1] = strings.TrimSuffix(repo[len(repo)-1], ".git")
	src.URL = u.Scheme + "://" + u.Host + "/" + strings.Join(repo, "/")
	return src, nil
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// splitRepo takes the first n segments as the repository and, when the next segment is
// one of markers, the one after it as the ref and the rest as a folder.
func splitRepo(segs []string, n int, markers ...string) (repo []string, ref, folder string) {
	if len(segs) < n {
		return segs, "", ""
	}
	repo, rest := segs[:n], segs[n:]
	if len(rest) >= 2 {
		for _, m := range markers {
			if rest[0] == m {
				return repo, rest[1], strings.Join(rest[2:], "/")
			}
		}
	}
	return repo, "", ""
}

// Name is a short default name for the source: the repository name, or the archive's
// file name without its extension.
func (s Source) Name() string {
	segs := splitPath(strings.SplitN(strings.SplitN(s.URL, "?", 2)[0], "://", 2)[1])
	if len(segs) == 0 {
		return s.URL
	}
	if s.Kind == KindArchive {
		base := segs[len(segs)-1]
		for _, ext := range []string{".tar.gz", ".tgz", ".zip"} {
			if strings.HasSuffix(strings.ToLower(base), ext) {
				return base[:len(base)-len(ext)]
			}
		}
		return base
	}
	if len(segs) >= 3 {
		return segs[len(segs)-2] + "/" + segs[len(segs)-1]
	}
	return segs[len(segs)-1]
}

// archiveURLs returns where a git host serves a tar.gz of the given commit, most likely
// layout first. Unrecognized hosts are tried as Gitea and then as GitLab.
func (s Source) archiveURLs(commit string) []string {
	gitea := s.URL + "/archive/" + commit + ".tar.gz"
	gitlab := s.URL + "/-/archive/" + commit + "/" + path.Base(s.URL) + "-" + commit + ".tar.gz"
	switch s.Host {
	case HostGitHub:
		return []string{s.URL + "/archive/" + commit + ".tar.gz"}
	case HostGitLab:
		return []string{gitlab}
	case HostBitbucket:
		return []string{s.URL + "/get/" + commit + ".tar.gz"}
	default:
		return []string{gitea, gitlab}
	}
}

// FileURL links to a file in a git repository at a version, or to the folder when file
// is empty. It returns "" for archives.
func (s Source) FileURL(version, file string) string {
	if s.Kind != KindGit || version == "" {
		return ""
	}
	tail := ""
	if file != "" {
		tail = "/" + file
	}
	switch s.Host {
	case HostGitHub:
		if file == "" {
			return s.URL + "/tree/" + version
		}
		return s.URL + "/blob/" + version + tail
	case HostGitLab:
		if file == "" {
			return s.URL + "/-/tree/" + version
		}
		return s.URL + "/-/blob/" + version + tail
	case HostBitbucket:
		return s.URL + "/src/" + version + tail
	default:
		return s.URL + "/src/commit/" + version + tail
	}
}

// CleanFolder normalizes a folder inside a repository ("rules/windows/"); it returns ""
// for the whole repository and an error for paths that leave it.
func CleanFolder(f string) (string, error) {
	f = strings.Trim(strings.ReplaceAll(strings.TrimSpace(f), `\`, "/"), "/")
	if f == "" || f == "." {
		return "", nil
	}
	c := path.Clean(f)
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("folder %q is outside the repository", f)
	}
	return c, nil
}

// InFolders reports whether a file (slash-separated, relative to the repository root)
// is inside one of folders. No folders means the whole repository.
func InFolders(file string, folders []string) bool {
	if len(folders) == 0 {
		return true
	}
	for _, f := range folders {
		if f == "" || file == f || strings.HasPrefix(file, f+"/") {
			return true
		}
	}
	return false
}
