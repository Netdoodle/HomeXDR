package core

import (
	"strings"
	"testing"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
)

const gib = int64(1) << 30

// days builds n days of usage ending today, each of size per.
func days(now time.Time, n int, per int64) []events.DayUsage {
	today := now.Truncate(24 * time.Hour)
	out := make([]events.DayUsage, n)
	for i := range out {
		out[i] = events.DayUsage{Day: today.AddDate(0, 0, i-n+1), Bytes: per, Events: 1000}
	}
	return out
}

func TestProjectRetention(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	// 1 TB cap, 100 days of 5 GiB = 500 GiB stored, no time limit.
	st := &RetentionStatus{Settings: RetentionSettings{MaxBytes: 1 << 40}, Days: days(now, 100, 5*gib)}
	projectRetention(st, now)
	if st.StoredBytes != 500*gib || st.DailyAvgBytes != 5*gib || st.Oldest == nil {
		t.Fatalf("totals: %+v", st)
	}
	// 524 GiB headroom at 5 GiB a day: about 104.8 days from now.
	want := now.Add(time.Duration(524.0 / 5 * float64(24*time.Hour)))
	if st.NextReason != "size" || st.NextFalloff == nil || st.NextFalloff.Sub(want).Abs() > time.Minute {
		t.Fatalf("size falloff = %v (%s), want %v", st.NextFalloff, st.NextReason, want)
	}
	if st.CoverageDays < 204 || st.CoverageDays > 205 {
		t.Errorf("coverage = %v days, want 204.8", st.CoverageDays)
	}
	if !st.NextRemovesDay.Equal(*st.Oldest) {
		t.Errorf("removes day %v, want the oldest %v", st.NextRemovesDay, st.Oldest)
	}

	// A 120-day limit: the oldest day (99 days ago) goes at the start of day oldest+121.
	st = &RetentionStatus{Settings: RetentionSettings{Days: 120, MaxBytes: 1 << 40}, Days: days(now, 100, 5*gib)}
	projectRetention(st, now)
	wantT := st.Oldest.AddDate(0, 0, 121)
	if st.NextReason != "time" || !st.NextFalloff.Equal(wantT) {
		t.Fatalf("time falloff = %v (%s), want %v", st.NextFalloff, st.NextReason, wantT)
	}
}

func TestPreviewRetention(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	u := &events.Usage{Days: days(now, 100, 5*gib), DiskTotal: 4 << 40, DiskFree: 2 << 40}
	cur := RetentionSettings{MaxBytes: 1 << 40}

	// Raising the cap removes nothing and is not a reduction.
	pv := previewRetention(cur, RetentionSettings{MaxBytes: 2 << 40}, u, now)
	if pv.Reduction || pv.RemovesEvents != 0 {
		t.Fatalf("raise: %+v", pv)
	}

	// A 200 GiB cap keeps the newest 40 days and removes the oldest 60.
	pv = previewRetention(cur, RetentionSettings{MaxBytes: 200 * gib}, u, now)
	if !pv.Reduction || pv.RemovesBytes != 300*gib || pv.RemovesEvents != 60000 {
		t.Fatalf("cap cut: %+v", pv)
	}
	if !pv.KeepsFrom.Equal(u.Days[60].Day) || !pv.RemovesUntil.Equal(u.Days[60].Day) {
		t.Errorf("keeps from %v, removes until %v", pv.KeepsFrom, pv.RemovesUntil)
	}
	if len(pv.Warnings) < 3 || !strings.Contains(pv.Warnings[0], "permanently deleted") {
		t.Errorf("warnings = %q", pv.Warnings)
	}

	// A 30-day limit removes the days before the cutoff.
	pv = previewRetention(cur, RetentionSettings{Days: 30, MaxBytes: 1 << 40}, u, now)
	if pv.RemovesEvents != 69000 || !pv.Reduction { // keeps the cutoff day through today: 31 days
		t.Fatalf("days cut: %+v", pv)
	}

	// A cap bigger than the disk can hold is called out.
	pv = previewRetention(cur, RetentionSettings{MaxBytes: 10 << 40}, u, now)
	if !strings.Contains(strings.Join(pv.Warnings, " "), "larger than the disk") {
		t.Errorf("disk warning missing: %q", pv.Warnings)
	}
	// Today is never removed, even by a tiny cap.
	pv = previewRetention(cur, RetentionSettings{MaxBytes: gib}, u, now)
	if pv.RemovesEvents != 99000 {
		t.Errorf("tiny cap removes %d events, want all but today", pv.RemovesEvents)
	}
}

func TestRetentionValidate(t *testing.T) {
	for _, s := range []RetentionSettings{{Days: -1}, {Days: 40000}, {MaxBytes: 1 << 20}, {MaxBytes: -5}} {
		if s.validate() == nil {
			t.Errorf("%+v accepted", s)
		}
	}
	if (RetentionSettings{Days: 0, MaxBytes: 0}).validate() != nil || (RetentionSettings{Days: 90, MaxBytes: 1 << 40}).validate() != nil {
		t.Error("valid settings rejected")
	}
}
