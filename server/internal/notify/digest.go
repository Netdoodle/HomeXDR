package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

const (
	digestStateKey   = "notify_digest_state"
	digestMaxRules   = 15
	digestMaxShapes  = 5
	digestMaxVerdict = 5
)

// LastDigest and NextDigest say when the digest last ran and when it will next, for the
// settings page. Either is nil when it does not apply.
func (s *Service) digestTimes(ctx context.Context, set Settings) (last, next *time.Time) {
	var state digestState
	if err := s.st.GetKV(ctx, digestStateKey, &state); err == nil {
		last = &state.LastRun
	}
	if set.DigestEnabled && len(set.enabledChannels()) > 0 {
		if due, err := scheduledTime(set, s.now()); err == nil {
			t := due.AddDate(0, 0, 1)
			next = &t
		}
	}
	return last, next
}

// digestState survives restarts, so a digest is neither repeated nor lost.
type digestState struct {
	LastRun time.Time `json:"last_run"`
}

// scheduledTime returns the most recent digest time at or before now.
func scheduledTime(set Settings, now time.Time) (time.Time, error) {
	t, err := time.Parse("15:04", set.DigestTime)
	if err != nil {
		return time.Time{}, err
	}
	local := now.In(set.location())
	at := time.Date(local.Year(), local.Month(), local.Day(), t.Hour(), t.Minute(), 0, 0, local.Location())
	if at.After(local) {
		at = at.AddDate(0, 0, -1)
	}
	return at, nil
}

// digestIfDue queues the digest when its time has passed since the last run. A digest
// missed while the server was down goes out when it comes back.
func (s *Service) digestIfDue(ctx context.Context) error {
	set := s.Settings(ctx)
	channels := set.enabledChannels()
	if !set.DigestEnabled || len(channels) == 0 {
		return nil
	}
	now := s.now()
	due, err := scheduledTime(set, now)
	if err != nil {
		return err
	}
	var state digestState
	if err := s.st.GetKV(ctx, digestStateKey, &state); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		// First time since notifications were set up: start counting from here, so
		// the first digest does not arrive the moment a channel is added.
		return s.st.SetKV(ctx, digestStateKey, digestState{LastRun: now})
	}
	if !state.LastRun.Before(due) {
		return nil
	}
	if err := s.queueDigest(ctx, set, channels, state.LastRun); err != nil {
		return err
	}
	return s.st.SetKV(ctx, digestStateKey, digestState{LastRun: now})
}

// queueDigest builds the digest and puts it in the outbox, unless there is nothing to
// say and the owner has not asked for a heartbeat.
func (s *Service) queueDigest(ctx context.Context, set Settings, channels []Channel, since time.Time) error {
	m, hasNews, err := s.buildDigest(ctx, set, since)
	if err != nil {
		return err
	}
	if !hasNews && !set.Heartbeat {
		return nil
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	items := make([]store.OutboxItem, len(channels))
	for i, c := range channels {
		items[i] = store.OutboxItem{ChannelID: c.ID, Kind: store.NotifyKindDigest, Payload: payload}
	}
	if err := s.st.EnqueueNotifications(ctx, s.now(), items); err != nil {
		return err
	}
	s.poke()
	return nil
}

// buildDigest writes the digest for what happened since `since`, and reports whether
// any of it is news. All text from alerts or other features is cleaned and defanged.
func (s *Service) buildDigest(ctx context.Context, set Settings, since time.Time) (Message, bool, error) {
	var m Message
	rules, err := s.st.DigestRuleCounts(ctx, since)
	if err != nil {
		return m, false, err
	}
	suppressed, err := s.st.SuppressedHitsSince(ctx, since)
	if err != nil {
		return m, false, err
	}
	overflow, err := s.st.OverflowSince(ctx, since)
	if err != nil {
		return m, false, err
	}

	bySeverity := map[string]int{}
	var shown []store.DigestRuleCount
	logged, total := 0, 0
	for _, r := range rules {
		bySeverity[r.Severity] += r.Alerts
		total += r.Alerts
		if set.Route(r.Severity, r.RuleID) == RouteLog {
			logged += r.Alerts
			continue
		}
		shown = append(shown, r)
	}

	var b strings.Builder
	section := func(title string) {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(untrusted(title, 200) + "\n")
	}

	section("Alerts since " + since.In(set.location()).Format("2006-01-02 15:04 MST"))
	if total == 0 {
		b.WriteString("No alerts.\n")
	} else {
		var parts []string
		for _, sev := range []string{store.SevCritical, store.SevHigh, store.SevMedium, store.SevLow, store.SevInformational} {
			if n := bySeverity[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, sev))
			}
		}
		b.WriteString(strings.Join(parts, ", ") + "\n")
	}
	if overflow > 0 {
		fmt.Fprintf(&b, "%d more went over your limit of %d an hour and were not sent at the time.\n", overflow, set.RatePerHour)
	}
	if logged > 0 {
		fmt.Fprintf(&b, "%d of them are only logged, and not listed here.\n", logged)
	}

	if len(shown) > 0 {
		section("By rule")
		for i, r := range shown {
			if i == digestMaxRules {
				fmt.Fprintf(&b, "and %d more rules\n", len(shown)-digestMaxRules)
				break
			}
			fmt.Fprintf(&b, "%d x %s (%s, %d %s)\n", r.Hits, untrusted(firstOf(r.Title, r.RuleID), 120), untrusted(r.Severity, 20), r.Alerts, plural(r.Alerts, "alert"))
		}
	}

	shapes, err := s.st.TopRepeating(ctx, since, digestMaxShapes)
	if err != nil {
		return m, false, err
	}
	if len(shapes) > 0 {
		section("Top repeating")
		for _, sh := range shapes {
			fmt.Fprintf(&b, "%d x %s on %s", sh.Hits, untrusted(firstOf(sh.RuleTitle, sh.RuleID), 100), untrusted(sh.Hostname, 60))
			if sh.Process != "" {
				fmt.Fprintf(&b, ": %s", untrusted(sh.Process, 120))
			}
			if sh.Parent != "" {
				fmt.Fprintf(&b, " from %s", untrusted(sh.Parent, 120))
			}
			b.WriteString("\n")
		}
	}

	if suppressed > 0 {
		section("Suppressed")
		fmt.Fprintf(&b, "%d %s closed by suppressions.\n", suppressed, plural(int(suppressed), "hit"))
	}

	counts, verdicts, err := s.st.DigestVerdicts(ctx, since, digestMaxVerdict)
	if err != nil {
		return m, false, err
	}
	if len(counts) > 0 {
		section("AI analyst")
		var parts []string
		for _, v := range []string{"malicious", "suspicious", "inconclusive", "benign"} {
			if n := counts[v]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, v))
			}
		}
		b.WriteString(strings.Join(parts, ", ") + "\n")
		for _, v := range verdicts {
			fmt.Fprintf(&b, "%s: %s on %s", v.Verdict, untrusted(firstOf(v.Title, v.AlertID), 100), untrusted(v.Hostname, 60))
			if set.ConsoleURL != "" {
				fmt.Fprintf(&b, " %s/alerts/%s", set.ConsoleURL, v.AlertID)
			}
			b.WriteString("\n")
		}
	}

	s.mu.Lock()
	extras := append([]digestSection(nil), s.sections...)
	s.mu.Unlock()
	extraLines := 0
	for _, sec := range extras {
		lines, err := sec.fn(ctx, since)
		if err != nil {
			s.log.Warn("notify: digest section", "section", sec.title, "err", err)
			continue
		}
		if len(lines) == 0 {
			continue
		}
		extraLines += len(lines)
		section(sec.title)
		for _, l := range lines {
			b.WriteString(untrusted(l, 400) + "\n")
		}
	}

	hasNews := total > 0 || suppressed > 0 || overflow > 0 || extraLines > 0
	title := "HomeXDR daily digest: nothing to report"
	if hasNews {
		title = fmt.Sprintf("HomeXDR daily digest: %d %s", total, plural(total, "alert"))
		if suppressed > 0 {
			title += fmt.Sprintf(", %d suppressed", suppressed)
		}
	}
	m = Message{Kind: store.NotifyKindDigest, Title: title, Body: strings.TrimRight(b.String(), "\n"), Link: set.ConsoleURL}
	return m, hasNews, nil
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
