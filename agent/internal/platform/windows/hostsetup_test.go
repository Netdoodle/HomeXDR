//go:build windows

package windows

import (
	"encoding/json"
	"testing"
)

func TestAuditBackupOldFile(t *testing.T) {
	old := `{"Creation":1,"Termination":2,"CommandLine":true,"CommandLineSet":true}`
	bk, err := parseAuditBackup([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if bk.TaskSchedulerLog != nil {
		t.Errorf("old file: TaskSchedulerLog = %v, want nil", *bk.TaskSchedulerLog)
	}
	if bk.Creation != 1 || bk.Termination != 2 || !bk.CommandLine || !bk.CommandLineSet {
		t.Errorf("old file fields lost: %+v", bk.ProcessAudit)
	}
	b, _ := json.Marshal(bk)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["TaskSchedulerLogWasEnabled"]; ok {
		t.Errorf("unknown state must be omitted: %s", b)
	}
}

func TestAuditBackupRoundTrip(t *testing.T) {
	for _, was := range []bool{false, true} {
		in := auditBackup{ProcessAudit: ProcessAudit{Creation: 3, Termination: 1, CommandLine: true}, TaskSchedulerLog: &was}
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		out, err := parseAuditBackup(b)
		if err != nil {
			t.Fatal(err)
		}
		if out.TaskSchedulerLog == nil || *out.TaskSchedulerLog != was {
			t.Errorf("was=%v: got %v (%s)", was, out.TaskSchedulerLog, b)
		}
		if out.ProcessAudit != in.ProcessAudit {
			t.Errorf("audit fields changed: %+v vs %+v", out.ProcessAudit, in.ProcessAudit)
		}
	}
}
