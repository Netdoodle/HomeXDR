package vuln

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/lists"
)

// EPSS is FIRST's Exploit Prediction Scoring System: for every published CVE, the chance it is
// exploited in the next 30 days. It is one CSV file, refreshed daily.
const (
	EPSSListID   = "epss"
	epssFileName = "epss_scores-current.csv.gz"
	epssURL      = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

type epssScore struct {
	Prob, Percentile float32
}

type epssTable struct {
	scores map[string]epssScore
	date   string
}

func (s *Service) registerEPSS(l *lists.Service) {
	l.Register(&lists.Source{
		ID: EPSSListID, Name: "Exploit prediction scores (FIRST EPSS)",
		About:   "For every CVE, the chance it is exploited in the next 30 days. Used in the risk score on the Vulnerabilities page.",
		SiteURL: "https://www.first.org/epss/", DefaultOn: true, Every: 24 * time.Hour, MaxBytes: 64 << 20, MinEntries: 10000,
		License: "Free to use, with credit to FIRST.", LicenseURL: "https://www.first.org/epss/user-guide",
		Files: func(time.Time) []lists.RemoteFile { return []lists.RemoteFile{{Name: epssFileName, URL: epssURL}} },
		Load: func(dir string) (func(), int, error) {
			t, err := parseEPSS(filepath.Join(dir, epssFileName))
			if err != nil {
				return nil, 0, err
			}
			return func() {
				s.epss.Store(t)
				s.Poke()
			}, len(t.scores), nil
		},
		Clear: func() { s.epss.Store(nil) },
	})
}

// parseEPSS reads the gzipped CSV: a "#model_version:...,score_date:..." line, a header, then
// cve,epss,percentile rows.
func parseEPSS(path string) (*epssTable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("not a gzip file: %w", err)
	}
	defer zr.Close()
	t := &epssTable{scores: make(map[string]epssScore, 320000)}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			if _, after, ok := strings.Cut(line, "score_date:"); ok {
				t.date, _, _ = strings.Cut(after, "T")
			}
			continue
		}
		cve, rest, ok := strings.Cut(line, ",")
		if !ok || !strings.HasPrefix(cve, "CVE-") {
			continue
		}
		p, pct, _ := strings.Cut(rest, ",")
		prob, err1 := strconv.ParseFloat(p, 32)
		perc, err2 := strconv.ParseFloat(pct, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		t.scores[cve] = epssScore{float32(prob), float32(perc)}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("could not read the file: %w", err)
	}
	return t, nil
}
