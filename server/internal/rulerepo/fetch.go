package rulerepo

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Limits on what a download may contain. Rule repositories are small (SigmaHQ is about
// 10 MB as a tar.gz), so these only stop mistakes and hostile archives.
const (
	DefaultMaxDownload = 256 << 20 // compressed archive
	DefaultMaxFiles    = 50000     // .yml/.yaml files kept
	DefaultMaxTotal    = 256 << 20 // bytes of .yml/.yaml kept
	MaxFileSize        = 1 << 20   // larger rule files are skipped
)

// Remote identifies a downloaded version. Version is the commit for git repositories and
// "sha256:<hex>" of the archive for archive URLs; ETag and LastModified let archive
// checks skip the download when nothing changed.
type Remote struct {
	Version      string
	ETag         string
	LastModified string
}

// Stats describes an extracted download.
type Stats struct {
	Files   int // rule files kept
	Bytes   int64
	Skipped int // .yml/.yaml files over MaxFileSize
}

// Fetcher downloads sources over HTTP(S). The zero value is ready to use.
type Fetcher struct {
	Client      *http.Client // default: 5 minute timeout, proxy from the environment
	UserAgent   string
	MaxDownload int64
	MaxFiles    int
	MaxTotal    int64
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (f *Fetcher) get(ctx context.Context, u string, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	ua := f.UserAgent
	if ua == "" {
		ua = "homexdr"
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	return f.client().Do(req)
}

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// IsCommit reports whether ref is a full commit hash (SHA-1 or SHA-256).
func IsCommit(ref string) bool { return commitRe.MatchString(ref) }

// Latest returns the newest version of the source at ref ("" = the default branch)
// without extracting anything. For archives it downloads the file unless the server
// says it has not changed since have.
func (f *Fetcher) Latest(ctx context.Context, src Source, ref string, have Remote) (Remote, error) {
	if src.Kind == KindGit {
		commit, err := f.resolve(ctx, src, ref)
		return Remote{Version: commit}, err
	}
	tmp, rem, err := f.downloadArchive(ctx, src.URL, have, "")
	if tmp != "" {
		os.Remove(tmp)
	}
	return rem, err
}

// Fetch downloads the source at ref into dir, which must not exist yet, unless the
// newest version is the one in have. changed reports whether dir was written.
func (f *Fetcher) Fetch(ctx context.Context, src Source, ref string, have Remote, dir string) (rem Remote, st Stats, changed bool, err error) {
	if _, err := os.Lstat(dir); err == nil {
		return have, st, false, fmt.Errorf("rulerepo: %s already exists", dir)
	}
	work := filepath.Dir(dir)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return have, st, false, err
	}
	var tmp string
	strip := false
	if src.Kind == KindGit {
		commit, err := f.resolve(ctx, src, ref)
		if err != nil {
			return have, st, false, err
		}
		rem = Remote{Version: commit}
		if commit == have.Version {
			return have, st, false, nil
		}
		// Git host archives put everything under one top-level folder (repo-<commit>/).
		strip = true
		var lastErr error
		for _, u := range src.archiveURLs(commit) {
			tmp, _, lastErr = f.downloadArchive(ctx, u, Remote{}, work)
			if lastErr == nil {
				break
			}
		}
		if lastErr != nil {
			return have, st, false, lastErr
		}
	} else {
		tmp, rem, err = f.downloadArchive(ctx, src.URL, have, work)
		if err != nil || tmp == "" || rem.Version == have.Version {
			if tmp != "" {
				os.Remove(tmp)
			}
			return rem, st, false, err
		}
	}
	defer os.Remove(tmp)
	if st, err = f.extract(tmp, dir, strip); err != nil {
		os.RemoveAll(dir)
		return have, st, false, err
	}
	return rem, st, true, nil
}

// resolve returns the commit that ref names, reading the repository's ref
// advertisement. A full commit hash is returned as is.
func (f *Fetcher) resolve(ctx context.Context, src Source, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if IsCommit(ref) {
		return ref, nil
	}
	u := src.URL + ".git/info/refs?service=git-upload-pack"
	resp, err := f.get(ctx, u, map[string]string{"Accept": "application/x-git-upload-pack-advertisement"})
	if err != nil {
		return "", fmt.Errorf("could not reach %s: %w", src.URL, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return "", fmt.Errorf("%s was not found or is not public (HTTP %d)", src.URL, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("%s answered HTTP %d", src.URL, resp.StatusCode)
	case !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/x-git-upload-pack-advertisement"):
		return "", fmt.Errorf("%s does not look like a git repository", src.URL)
	}
	refs, err := parseAdvertisement(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", fmt.Errorf("%s: %w", src.URL, err)
	}
	if ref == "" {
		if c := refs["HEAD"]; c != "" {
			return c, nil
		}
		return "", fmt.Errorf("%s has no default branch", src.URL)
	}
	candidates := []string{ref}
	if !strings.HasPrefix(ref, "refs/") {
		candidates = []string{"refs/heads/" + ref, "refs/tags/" + ref}
	}
	for _, name := range candidates {
		// An annotated tag's peeled entry names the commit; the plain one names the tag object.
		if c := refs[name+"^{}"]; c != "" {
			return c, nil
		}
		if c := refs[name]; c != "" {
			return c, nil
		}
	}
	return "", fmt.Errorf("%s has no branch or tag named %q", src.URL, ref)
}

// parseAdvertisement reads git's smart-HTTP ref advertisement (pkt-lines) into ref name
// → object id.
func parseAdvertisement(r io.Reader) (map[string]string, error) {
	br := bufio.NewReader(r)
	refs := map[string]string{}
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.New("truncated ref advertisement")
		}
		n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
		if err != nil {
			return nil, errors.New("not a git ref advertisement")
		}
		if n == 0 { // flush-pkt
			continue
		}
		if n < 4 {
			return nil, errors.New("bad pkt-line length")
		}
		line := make([]byte, n-4)
		if _, err := io.ReadFull(br, line); err != nil {
			return nil, errors.New("truncated ref advertisement")
		}
		line = bytes.TrimRight(line, "\n")
		if i := bytes.IndexByte(line, 0); i >= 0 { // capabilities follow the first ref
			line = line[:i]
		}
		if bytes.HasPrefix(line, []byte("#")) {
			continue
		}
		id, name, ok := bytes.Cut(line, []byte(" "))
		if !ok || !commitRe.Match(id) {
			continue
		}
		refs[string(name)] = string(id)
	}
	if len(refs) == 0 {
		return nil, errors.New("the repository advertised no branches (is it empty?)")
	}
	return refs, nil
}

// downloadArchive saves u to a temporary file in dir and returns it with its version
// (sha256 of the content). With have's validators it sends a conditional request; when
// the server answers 304 it returns have and no file. dir "" discards the content after
// hashing it.
func (f *Fetcher) downloadArchive(ctx context.Context, u string, have Remote, dir string) (string, Remote, error) {
	resp, err := f.get(ctx, u, map[string]string{"If-None-Match": have.ETag, "If-Modified-Since": have.LastModified})
	if err != nil {
		return "", have, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && have.Version != "" {
		return "", have, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", have, fmt.Errorf("download of %s failed: HTTP %d", u, resp.StatusCode)
	}
	max := f.MaxDownload
	if max <= 0 {
		max = DefaultMaxDownload
	}
	if resp.ContentLength > max {
		return "", have, fmt.Errorf("%s is larger than %d MB", u, max>>20)
	}
	h := sha256.New()
	var out io.Writer = h
	var tmp *os.File
	if dir != "" {
		if tmp, err = os.CreateTemp(dir, ".download-*"); err != nil {
			return "", have, err
		}
		out = io.MultiWriter(h, tmp)
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, max+1))
	if tmp != nil {
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
	}
	if err == nil && n > max {
		err = fmt.Errorf("%s is larger than %d MB", u, max>>20)
	}
	if err != nil {
		if tmp != nil {
			os.Remove(tmp.Name())
		}
		return "", have, fmt.Errorf("download of %s failed: %w", u, err)
	}
	rem := Remote{
		Version:      "sha256:" + hex.EncodeToString(h.Sum(nil)),
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}
	if tmp == nil {
		return "", rem, nil
	}
	return tmp.Name(), rem, nil
}

// extract writes the .yml/.yaml files of a tar.gz or zip archive to dir. With strip the
// first path component (the archive's top-level folder) is dropped. Hidden folders
// (.github), links and anything that would land outside dir are skipped.
func (f *Fetcher) extract(file, dir string, strip bool) (Stats, error) {
	var st Stats
	fh, err := os.Open(file)
	if err != nil {
		return st, err
	}
	defer fh.Close()
	var magic [4]byte
	if _, err := io.ReadFull(fh, magic[:]); err != nil {
		return st, errors.New("the download is not a .zip or .tar.gz archive")
	}
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		return st, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return st, err
	}
	maxFiles, maxTotal := f.MaxFiles, f.MaxTotal
	if maxFiles <= 0 {
		maxFiles = DefaultMaxFiles
	}
	if maxTotal <= 0 {
		maxTotal = DefaultMaxTotal
	}
	write := func(name string, size int64, open func() (io.ReadCloser, error)) error {
		rel, ok := rulePath(name, strip)
		if !ok {
			return nil
		}
		if size > MaxFileSize {
			st.Skipped++
			return nil
		}
		if st.Files >= maxFiles {
			return fmt.Errorf("the archive has more than %d rule files", maxFiles)
		}
		if st.Bytes+size > maxTotal {
			return fmt.Errorf("the archive's rule files are larger than %d MB in total", maxTotal>>20)
		}
		rc, err := open()
		if err != nil {
			return err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, MaxFileSize+1))
		if err != nil {
			return err
		}
		if int64(len(b)) > MaxFileSize {
			st.Skipped++
			return nil
		}
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return err
		}
		st.Files++
		st.Bytes += int64(len(b))
		return nil
	}

	switch {
	case magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(fh)
		if err != nil {
			return st, fmt.Errorf("bad tar.gz archive: %w", err)
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return st, fmt.Errorf("bad tar.gz archive: %w", err)
			}
			if h.Typeflag != tar.TypeReg {
				continue
			}
			if err := write(h.Name, h.Size, func() (io.ReadCloser, error) { return io.NopCloser(tr), nil }); err != nil {
				return st, err
			}
		}
	case string(magic[:]) == "PK\x03\x04":
		info, err := fh.Stat()
		if err != nil {
			return st, err
		}
		zr, err := zip.NewReader(fh, info.Size())
		if err != nil {
			return st, fmt.Errorf("bad zip archive: %w", err)
		}
		for _, zf := range zr.File {
			if !zf.Mode().IsRegular() {
				continue
			}
			if err := write(zf.Name, int64(zf.UncompressedSize64), zf.Open); err != nil {
				return st, err
			}
		}
	default:
		return st, errors.New("the download is not a .zip or .tar.gz archive")
	}
	if st.Files == 0 {
		return st, errors.New("no .yml or .yaml files found")
	}
	return st, nil
}

// rulePath returns where an archive entry goes, relative to the repository root, or
// false when it is not a rule file to keep.
func rulePath(name string, strip bool) (string, bool) {
	name = strings.ReplaceAll(name, `\`, "/")
	ext := strings.ToLower(path.Ext(name))
	if ext != ".yml" && ext != ".yaml" {
		return "", false
	}
	segs := splitPath(name)
	if strip {
		if len(segs) < 2 {
			return "", false
		}
		segs = segs[1:]
	}
	for _, s := range segs {
		if s == "." || s == ".." || strings.HasPrefix(s, ".") || strings.ContainsRune(s, ':') {
			return "", false
		}
	}
	if len(segs) == 0 {
		return "", false
	}
	return strings.Join(segs, "/"), true
}

// Folder is a folder in a downloaded repository with the number of rule files below it.
type Folder struct {
	Path  string `json:"path"`
	Files int    `json:"files"`
}

// Folders lists the folders under dir, up to three levels deep, that contain rule files,
// with recursive file counts, in path order.
func Folders(dir string) []Folder {
	counts := map[string]int{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		rel, err := filepath.Rel(dir, filepath.Dir(p))
		if err != nil || rel == "." {
			return nil
		}
		segs := strings.Split(filepath.ToSlash(rel), "/")
		for i := 1; i <= len(segs) && i <= 3; i++ {
			counts[strings.Join(segs[:i], "/")]++
		}
		return nil
	})
	out := make([]Folder, 0, len(counts))
	for p, n := range counts {
		out = append(out, Folder{Path: p, Files: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if len(out) > 2000 {
		out = out[:2000]
	}
	return out
}
