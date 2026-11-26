package vuln

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Application is one line of a host's software list as the agent last reported it.
type Application struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Type         string `json:"type,omitempty"`
	Source       string `json:"source,omitempty"`
	Vendor       string `json:"vendor,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	InstallPath  string `json:"install_path,omitempty"`
}

// Applications returns a host's newest software list, sorted by name, and when the
// agent reported it (zero when there is no list from the last inventoryDays).
func (s *Service) Applications(ctx context.Context, hostID string) ([]Application, time.Time, error) {
	now := time.Now()
	return s.applications(ctx, hostID, now)
}

func (s *Service) applications(ctx context.Context, hostID string, now time.Time) ([]Application, time.Time, error) {
	rows, at, err := s.inventoryEvents(ctx, hostID, now)
	if err != nil || len(rows) == 0 {
		return []Application{}, at, err
	}
	type key struct{ name, version, typ, arch string }
	seen := map[key]bool{}
	out := make([]Application, 0, len(rows))
	for _, e := range rows {
		if e.Package == nil || e.Package.Name == "" {
			continue
		}
		p := e.Package
		k := key{p.Name, p.Version, p.Type, p.Architecture}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, Application{Name: p.Name, Version: p.Version, Type: p.Type, Source: p.Source,
			Vendor: p.Vendor, Architecture: p.Architecture, InstallPath: p.InstallPath})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].Version < out[j].Version
	})
	return out, at, nil
}
