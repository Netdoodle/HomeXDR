package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

func TestRemoveHostDeletesWhatIsKeyedByIt(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, id := range []string{"gone", "stays"} {
		if _, err := s.CreateEndpoint(ctx, id, api.HostInfo{Hostname: id, OS: event.OS{Platform: "linux"}}, []string{"lab"}, "s"); err != nil {
			t.Fatal(err)
		}
		rec, err := s.CreateCommand(ctx, id, "file.hash", []byte(`{}`), "admin", "", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetUpload(ctx, rec.ID, "/tmp/"+id, "f"); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{
			`INSERT INTO command_rows(command_id, seq, host_id, row) VALUES('` + rec.ID + `', 1, '` + id + `', '{}')`,
			`INSERT INTO vuln_matches(host_id, package, cve, confidence, first_seen, last_seen) VALUES('` + id + `', 'p', 'CVE-1', 'confirmed', 'x', 'x')`,
			`INSERT INTO vuln_findings(host_id, package, cve, status, first_seen, last_seen) VALUES('` + id + `', 'p', 'CVE-1', 'open', 'x', 'x')`,
			`INSERT INTO feed_sources(host_id, module, dataset) VALUES('` + id + `', 'm', 'd')`,
			`INSERT INTO alerts(id, dedup_key, rule_id, rule, severity, risk_score, status, host_id, hostname, first_seen, last_seen, created_at, updated_at)
			 VALUES('a-` + id + `','k','r','{}','low',1,'new','` + id + `','` + id + `','x','x','x','x')`,
		} {
			if _, err := s.db.ExecContext(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	}
	uploads, err := s.RemoveHost(ctx, "gone")
	if err != nil || len(uploads) != 1 || uploads[0] != "/tmp/gone" {
		t.Fatalf("RemoveHost = %v, %v", uploads, err)
	}
	if _, err := s.RemoveHost(ctx, "gone"); err != ErrNotFound {
		t.Fatalf("second removal = %v", err)
	}
	count := func(table, col, id string) int {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE `+col+` = ?`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, tb := range []string{"hosts:id", "commands:host_id", "command_rows:host_id", "vuln_matches:host_id", "vuln_findings:host_id", "feed_sources:host_id"} {
		table, col, _ := strings.Cut(tb, ":")
		if n := count(table, col, "gone"); n != 0 {
			t.Errorf("%s still has %d rows for the removed host", table, n)
		}
		if n := count(table, col, "stays"); n != 1 {
			t.Errorf("%s has %d rows for the other host, want 1", table, n)
		}
	}
	if n := count("alerts", "host_id", "gone"); n != 1 {
		t.Errorf("alerts of a removed host must be kept, have %d", n)
	}
}
