package core

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/events"
	"github.com/Netdoodle/homexdr/server/internal/store"
)

// Event retention: a time limit (days) and a size cap (bytes), whichever removes events
// first. The environment (HOMEXDR_RETENTION_DAYS / _MAX_SIZE) sets the starting values;
// a change made in the console is stored and wins from then on.

const retentionKey = "retention_settings"

// RetentionSettings are the two limits; 0 means none.
type RetentionSettings struct {
	Days     int   `json:"days"`
	MaxBytes int64 `json:"max_bytes"`
}

// Smallest size cap accepted: below this a single day of events would not fit.
const minRetentionBytes = 1 << 30

// retentionState holds the settings in effect; read by the purge loop.
type retentionState struct {
	cur    atomic.Pointer[RetentionSettings]
	source atomic.Value // "environment" or "console"
}

// Retention returns the settings in effect.
func (c *Core) Retention() RetentionSettings {
	if p := c.retention.cur.Load(); p != nil {
		return *p
	}
	return RetentionSettings{Days: c.Cfg.RetentionDays, MaxBytes: c.Cfg.RetentionMaxBytes}
}

// initRetention loads a setting saved from the console and applies its time limit to
// the event store (ClickHouse was opened with the environment's).
func (c *Core) initRetention(ctx context.Context) {
	set := RetentionSettings{Days: c.Cfg.RetentionDays, MaxBytes: c.Cfg.RetentionMaxBytes}
	c.retention.source.Store("environment")
	var saved RetentionSettings
	err := c.State.GetKV(ctx, retentionKey, &saved)
	switch {
	case err == nil:
		set = saved
		c.retention.source.Store("console")
		if set.Days != c.Cfg.RetentionDays {
			if err := c.Events.SetRetentionDays(ctx, set.Days); err != nil {
				c.Log.Error("apply saved retention days", "err", err)
			}
		}
	case !errors.Is(err, store.ErrNotFound):
		c.Log.Error("load retention settings", "err", err)
	}
	c.retention.cur.Store(&set)
}

func (s RetentionSettings) validate() error {
	if s.Days < 0 || s.Days > 36500 {
		return invalid("days must be between 0 (no time limit) and 36500")
	}
	if s.MaxBytes < 0 || (s.MaxBytes > 0 && s.MaxBytes < minRetentionBytes) {
		return invalid("the size cap must be 0 (no cap) or at least 1 GiB")
	}
	return nil
}

// RetentionStatus is the Data retention page.
type RetentionStatus struct {
	Settings     RetentionSettings `json:"settings"`
	Source       string            `json:"source"` // environment | console
	EventStore   string            `json:"event_store"`
	StoredBytes  int64             `json:"stored_bytes"`
	StoredEvents int64             `json:"stored_events"`
	Oldest       *time.Time        `json:"oldest,omitempty"` // first day with events (UTC)
	DiskTotal    int64             `json:"disk_total"`
	DiskFree     int64             `json:"disk_free"`
	// DailyAvgBytes is the average of the last 7 complete days.
	DailyAvgBytes int64 `json:"daily_avg_bytes"`
	// CoverageDays is how many days of events fit under the size cap at the current rate.
	CoverageDays float64 `json:"coverage_days,omitempty"`
	// TimeFalloff / SizeFalloff are when each rule next removes events; NextFalloff is
	// the earlier one, NextReason which rule it is, NextRemovesDay the day that goes.
	TimeFalloff    *time.Time        `json:"time_falloff,omitempty"`
	SizeFalloff    *time.Time        `json:"size_falloff,omitempty"`
	NextFalloff    *time.Time        `json:"next_falloff,omitempty"`
	NextReason     string            `json:"next_reason,omitempty"` // time | size
	NextRemovesDay *time.Time        `json:"next_removes_day,omitempty"`
	Days           []events.DayUsage `json:"days"`
}

func (c *Core) usage(ctx context.Context) (*events.Usage, error) {
	u, err := c.Events.Usage(ctx)
	if err != nil {
		return nil, err
	}
	if u.DiskTotal == 0 {
		u.DiskTotal, u.DiskFree = diskSpace(c.Cfg.DataDir)
	}
	return u, nil
}

// RetentionStatus reports usage and when events next fall off.
func (c *Core) RetentionStatus(ctx context.Context) (*RetentionStatus, error) {
	u, err := c.usage(ctx)
	if err != nil {
		return nil, err
	}
	src, _ := c.retention.source.Load().(string)
	st := &RetentionStatus{Settings: c.Retention(), Source: src, EventStore: c.Cfg.EventStore,
		DiskTotal: u.DiskTotal, DiskFree: u.DiskFree, Days: u.Days}
	if st.Days == nil {
		st.Days = []events.DayUsage{}
	}
	projectRetention(st, time.Now().UTC())
	return st, nil
}

// projectRetention fills the totals and falloff dates from st.Days and st.Settings.
func projectRetention(st *RetentionStatus, now time.Time) {
	today := now.Truncate(24 * time.Hour)
	st.StoredBytes, st.StoredEvents = 0, 0
	for _, d := range st.Days {
		st.StoredBytes += d.Bytes
		st.StoredEvents += d.Events
	}
	if len(st.Days) == 0 {
		return
	}
	oldest := st.Days[0].Day
	st.Oldest = &oldest
	// Average of the last 7 complete days (fewer when the store is newer).
	var sum int64
	var n int
	for i := len(st.Days) - 1; i >= 0 && n < 7; i-- {
		if st.Days[i].Day.Before(today) {
			sum += st.Days[i].Bytes
			n++
		}
	}
	if n > 0 {
		st.DailyAvgBytes = sum / int64(n)
	}
	set := st.Settings
	if set.Days > 0 {
		// A day's events go once its last event is older than the limit: at the start of
		// day (oldest + days + 1).
		t := oldest.AddDate(0, 0, set.Days+1)
		if t.Before(now) {
			t = now // overdue: removed at the next purge
		}
		st.TimeFalloff = &t
	}
	if set.MaxBytes > 0 && st.DailyAvgBytes > 0 {
		st.CoverageDays = float64(set.MaxBytes) / float64(st.DailyAvgBytes)
		headroom := set.MaxBytes - st.StoredBytes
		t := now
		if headroom > 0 {
			t = now.Add(time.Duration(float64(headroom) / float64(st.DailyAvgBytes) * float64(24*time.Hour)))
		}
		st.SizeFalloff = &t
	}
	switch {
	case st.TimeFalloff != nil && (st.SizeFalloff == nil || !st.SizeFalloff.Before(*st.TimeFalloff)):
		st.NextFalloff, st.NextReason = st.TimeFalloff, "time"
	case st.SizeFalloff != nil:
		st.NextFalloff, st.NextReason = st.SizeFalloff, "size"
	}
	if st.NextFalloff != nil {
		st.NextRemovesDay = &oldest
	}
}

// RetentionPreview says what new settings would do.
type RetentionPreview struct {
	Current   RetentionSettings `json:"current"`
	Proposed  RetentionSettings `json:"proposed"`
	Reduction bool              `json:"reduction"`
	// Events removed as soon as the change applies.
	RemovesBytes  int64      `json:"removes_bytes"`
	RemovesEvents int64      `json:"removes_events"`
	RemovesFrom   *time.Time `json:"removes_from,omitempty"`
	RemovesUntil  *time.Time `json:"removes_until,omitempty"` // exclusive
	KeepsFrom     *time.Time `json:"keeps_from,omitempty"`
	NextFalloff   *time.Time `json:"next_falloff,omitempty"`
	NextReason    string     `json:"next_reason,omitempty"`
	CoverageDays  float64    `json:"coverage_days,omitempty"`
	Warnings      []string   `json:"warnings"`
}

// PreviewRetention computes the effect of new settings without changing anything.
func (c *Core) PreviewRetention(ctx context.Context, p RetentionSettings) (*RetentionPreview, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	u, err := c.usage(ctx)
	if err != nil {
		return nil, err
	}
	return previewRetention(c.Retention(), p, u, time.Now().UTC()), nil
}

func previewRetention(cur, p RetentionSettings, u *events.Usage, now time.Time) *RetentionPreview {
	today := now.Truncate(24 * time.Hour)
	pv := &RetentionPreview{Current: cur, Proposed: p, Warnings: []string{}}
	shorter := func(newV, oldV int64) bool { return newV > 0 && (oldV == 0 || newV < oldV) }
	pv.Reduction = shorter(int64(p.Days), int64(cur.Days)) || shorter(p.MaxBytes, cur.MaxBytes)

	// Walk the days oldest first: the time limit removes days before the cutoff, then
	// the size cap removes more until the rest fits (today is never removed).
	keep := 0
	var total int64
	for _, d := range u.Days {
		total += d.Bytes
	}
	if p.Days > 0 {
		cutoff := today.AddDate(0, 0, -p.Days)
		for keep < len(u.Days) && u.Days[keep].Day.Before(cutoff) {
			total -= u.Days[keep].Bytes
			keep++
		}
	}
	if p.MaxBytes > 0 {
		for keep < len(u.Days)-1 && total > p.MaxBytes {
			total -= u.Days[keep].Bytes
			keep++
		}
	}
	for _, d := range u.Days[:keep] {
		pv.RemovesBytes += d.Bytes
		pv.RemovesEvents += d.Events
	}
	if keep > 0 {
		from, until := u.Days[0].Day, u.Days[keep-1].Day.AddDate(0, 0, 1)
		pv.RemovesFrom, pv.RemovesUntil = &from, &until
	}
	if keep < len(u.Days) {
		k := u.Days[keep].Day
		pv.KeepsFrom = &k
	}
	st := &RetentionStatus{Settings: p, Days: u.Days[keep:]}
	projectRetention(st, now)
	pv.NextFalloff, pv.NextReason, pv.CoverageDays = st.NextFalloff, st.NextReason, st.CoverageDays

	if pv.RemovesEvents > 0 {
		pv.Warnings = append(pv.Warnings, fmt.Sprintf(
			"%d events (%s) from %s to %s will be permanently deleted within about 10 minutes of saving. There is no undo and HomeXDR keeps no backup.",
			pv.RemovesEvents, humanBytes(pv.RemovesBytes), pv.RemovesFrom.Format("Jan 2, 2006"), pv.RemovesUntil.AddDate(0, 0, -1).Format("Jan 2, 2006")))
		pv.Warnings = append(pv.Warnings,
			"Alerts from that period stay listed, but the events behind them are gone: search, hunts, process trees, the AI analyst and investigations can no longer see them.")
	}
	if pv.Reduction {
		pv.Warnings = append(pv.Warnings,
			"Less history means a shorter window to discover an intrusion after the fact: many compromises are found weeks or months later.")
	}
	if p.MaxBytes > 0 && st.DailyAvgBytes > 0 && pv.CoverageDays < 7 {
		pv.Warnings = append(pv.Warnings, fmt.Sprintf("At the current rate of %s a day the size cap holds only about %.1f days of events.",
			humanBytes(st.DailyAvgBytes), pv.CoverageDays))
	}
	if p.MaxBytes > 0 && u.DiskTotal > 0 && p.MaxBytes > total+u.DiskFree {
		pv.Warnings = append(pv.Warnings, fmt.Sprintf(
			"The size cap (%s) is larger than the disk can hold (%s free): the disk would fill before the cap is reached.",
			humanBytes(p.MaxBytes), humanBytes(u.DiskFree)))
	}
	if p.Days == 0 && p.MaxBytes == 0 {
		pv.Warnings = append(pv.Warnings, "With no time limit and no size cap, events are kept until the disk is full.")
	}
	return pv
}

// SetRetention applies new settings. A reduction must be confirmed by the caller (the
// console's two confirmation steps send acknowledge and the confirmation phrase).
func (c *Core) SetRetention(ctx context.Context, p RetentionSettings, acknowledged bool, phrase string) (*RetentionPreview, error) {
	pv, err := c.PreviewRetention(ctx, p)
	if err != nil {
		return nil, err
	}
	if !acknowledged {
		return nil, invalid("confirm the change: acknowledge is required")
	}
	if (pv.Reduction || pv.RemovesEvents > 0) && phrase != RetentionConfirmPhrase {
		return nil, invalid("reducing retention needs the confirmation phrase %q", RetentionConfirmPhrase)
	}
	old := c.Retention()
	if p.Days != old.Days {
		if err := c.Events.SetRetentionDays(ctx, p.Days); err != nil {
			return nil, fmt.Errorf("apply time limit: %w", err)
		}
	}
	if err := c.State.SetKV(ctx, retentionKey, p); err != nil {
		return nil, err
	}
	c.retention.cur.Store(&p)
	c.retention.source.Store("console")
	// Apply now rather than at the next loop pass.
	go func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
		defer cancel()
		c.applyRetention(bg)
	}()
	return pv, nil
}

// RetentionConfirmPhrase must be typed to reduce retention.
const RetentionConfirmPhrase = "DELETE EVENTS"

// applyRetention runs the time purge and the size trim once.
func (c *Core) applyRetention(ctx context.Context) {
	set := c.Retention()
	if set.Days > 0 {
		if err := c.Events.Purge(ctx, time.Now().AddDate(0, 0, -set.Days)); err != nil {
			c.Log.Warn("event retention purge", "err", err)
		}
	}
	if set.MaxBytes > 0 {
		c.trimEvents(ctx)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
