// Package notify tells the owner about alerts: at once through ntfy, Discord, email or a
// webhook, or in a daily digest. Nothing here runs on the ingest path except writing to an
// outbox in the state database. A background loop does all network work, so a slow or
// failing service cannot hold up ingest, and messages survive a restart.
package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/store"
)

const (
	loopInterval = 30 * time.Second
	// maxAttempts is how often a message is tried before it is given up on. With the
	// backoff below, that spreads over about four hours.
	maxAttempts  = 9
	firstBackoff = 30 * time.Second
	maxBackoff   = time.Hour
	batchSize    = 20
	keepFinished = 30 * 24 * time.Hour
)

// backoff returns the wait before the next try, after this many failed attempts.
func backoff(attempts int) time.Duration {
	d := firstBackoff
	for i := 1; i < attempts && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

// DigestSectionFunc supplies lines for a digest section, about what happened since
// `since`. No lines leaves the section out. The text is cleaned and defanged when sent.
type DigestSectionFunc func(ctx context.Context, since time.Time) ([]string, error)

type digestSection struct {
	title string
	fn    DigestSectionFunc
}

// Service sends notifications.
type Service struct {
	st     *store.Store
	log    *slog.Logger
	client *http.Client
	// smtpTLS replaces the TLS settings for mail (tests).
	smtpTLS func(host string) *tls.Config
	now     func() time.Time
	wake    chan struct{}

	mu       sync.Mutex
	sections []digestSection
}

// New returns a service. Call Run to start sending.
func New(st *store.Store, log *slog.Logger) *Service {
	return &Service{st: st, log: log, client: newHTTPClient(), now: time.Now, wake: make(chan struct{}, 1)}
}

// AddDigestSection adds a section to the daily digest. Other features call it once at
// startup. A section that fails is left out of that digest and logged.
func (s *Service) AddDigestSection(title string, fn DigestSectionFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sections = append(s.sections, digestSection{title: title, fn: fn})
}

func (s *Service) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// AlertCreated routes a new alert. It only writes to the outbox, so it is safe on the
// ingest path. A database error is logged, never returned: notifications must not get in
// the way of detection.
func (s *Service) AlertCreated(ctx context.Context, a *store.Alert) {
	if s == nil || a.Status == store.AlertSuppressed {
		return
	}
	set := s.Settings(ctx)
	channels := set.enabledChannels()
	if len(channels) == 0 || set.Route(a.Severity, a.Rule.ID) != RouteNow {
		return
	}
	if err := s.queueAlert(ctx, set, channels, a); err != nil {
		s.log.Warn("notify: queue alert", "alert", a.ID, "err", err)
		return
	}
	s.poke()
}

func (s *Service) queueAlert(ctx context.Context, set Settings, channels []Channel, a *store.Alert) error {
	hourAgo := s.now().Add(-time.Hour)
	sent, err := s.st.ImmediateAlertsSince(ctx, hourAgo)
	if err != nil {
		return err
	}
	if sent >= set.RatePerHour {
		return s.queueOverflow(ctx, set, channels, a, hourAgo)
	}
	m := alertMessage(set, a)
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	items := make([]store.OutboxItem, len(channels))
	for i, c := range channels {
		items[i] = store.OutboxItem{ChannelID: c.ID, Kind: store.NotifyKindAlert, AlertID: a.ID, Payload: payload}
	}
	return s.st.EnqueueNotifications(ctx, s.now(), items)
}

// queueOverflow records an alert over the cap for the digest. The first in any hour also
// sends one notice, so a flood is not silent until the next digest.
func (s *Service) queueOverflow(ctx context.Context, set Settings, channels []Channel, a *store.Alert, hourAgo time.Time) error {
	over, err := s.st.OverflowSince(ctx, hourAgo)
	if err != nil {
		return err
	}
	items := []store.OutboxItem{{ChannelID: "", Kind: store.NotifyKindAlert, AlertID: a.ID, Status: store.NotifyOverflow, Payload: json.RawMessage(`{}`)}}
	if over == 0 {
		link := ""
		if set.ConsoleURL != "" {
			link = set.ConsoleURL + "/alerts"
		}
		notice, err := json.Marshal(Message{
			Kind:  store.NotifyKindNotice,
			Title: "HomeXDR: more alerts than your hourly limit",
			Body: fmt.Sprintf("More than %d alerts arrived in the last hour. The rest of them go to the daily digest instead of your phone, so check the console.",
				set.RatePerHour),
			Severity: store.SevHigh,
			Link:     link,
		})
		if err != nil {
			return err
		}
		for _, c := range channels {
			items = append(items, store.OutboxItem{ChannelID: c.ID, Kind: store.NotifyKindNotice, Payload: notice})
		}
	}
	return s.st.EnqueueNotifications(ctx, s.now(), items)
}

// alertMessage writes an alert as text. Everything from the alert is treated as untrusted.
func alertMessage(set Settings, a *store.Alert) Message {
	var b strings.Builder
	line := func(label, value string, limit int) {
		if value != "" {
			fmt.Fprintf(&b, "%s: %s\n", label, untrusted(value, limit))
		}
	}
	line("Severity", a.Severity, 20)
	line("Rule", a.Rule.Title, 200)
	line("Host", a.Hostname, 100)
	line("User", a.User, 100)
	if a.Event != nil && a.Event.Process != nil {
		p := a.Event.Process
		line("Process", firstOf(p.Executable, p.Name), 300)
		if p.Parent != nil {
			line("Parent", firstOf(p.Parent.Executable, p.Parent.Name), 300)
		}
		line("Command", p.CommandLine, 400)
	} else if a.ProcessName != "" {
		line("Process", a.ProcessName, 300)
		line("Command", a.CommandLine, 400)
	} else if a.Event != nil {
		line("Message", a.Event.Message, 400)
	}
	line("Seen", a.FirstSeen.In(set.location()).Format("2006-01-02 15:04 MST"), 40)
	var techniques []string
	for _, m := range a.Mitre {
		if m.TechniqueID != "" {
			techniques = append(techniques, m.TechniqueID)
		}
	}
	line("MITRE", strings.Join(techniques, ", "), 200)
	if a.Suppression != nil && a.Suppression.Overridden {
		line("Note", "a suppression matched but this was kept: "+a.Suppression.Why, 200)
	}
	b.WriteString("Details above come from the monitored system and may be attacker-written. Links in them were made inert.")
	m := Message{
		Kind:     store.NotifyKindAlert,
		Title:    fmt.Sprintf("[%s] %s on %s", strings.ToUpper(untrusted(a.Severity, 20)), untrusted(a.Rule.Title, 120), untrusted(a.Hostname, 60)),
		Body:     b.String(),
		Severity: a.Severity,
		RuleID:   a.Rule.ID,
		AlertID:  a.ID,
	}
	if set.ConsoleURL != "" {
		m.Link = set.ConsoleURL + "/alerts/" + a.ID
	}
	return m
}

func firstOf(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Run sends queued messages and the daily digest until ctx ends.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(loopInterval)
	defer tick.Stop()
	lastPurge := time.Time{}
	for {
		s.deliverDue(ctx)
		if err := s.digestIfDue(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("notify: digest", "err", err)
		}
		if s.now().Sub(lastPurge) > 6*time.Hour {
			if _, err := s.st.PurgeNotifications(ctx, s.now().Add(-keepFinished)); err != nil && ctx.Err() == nil {
				s.log.Warn("notify: purge", "err", err)
			}
			lastPurge = s.now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-s.wake:
		}
	}
}

// deliverDue sends everything due. A full batch means there may be more, so it carries on.
func (s *Service) deliverDue(ctx context.Context) {
	for ctx.Err() == nil {
		due, err := s.st.DueNotifications(ctx, s.now(), batchSize)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("notify: read outbox", "err", err)
			}
			return
		}
		set := s.Settings(ctx)
		for _, it := range due {
			if ctx.Err() != nil {
				return
			}
			s.deliver(ctx, set, it)
		}
		if len(due) < batchSize {
			return
		}
	}
}

func (s *Service) deliver(ctx context.Context, set Settings, it store.OutboxItem) {
	finish := func(status, why string) {
		if err := s.st.FinishNotification(context.WithoutCancel(ctx), it.ID, status, why); err != nil {
			s.log.Warn("notify: update outbox", "err", err)
		}
	}
	c, ok := set.channel(it.ChannelID)
	if !ok || !c.Enabled {
		finish(store.NotifyDropped, "the channel was removed or turned off")
		return
	}
	var m Message
	if err := json.Unmarshal(it.Payload, &m); err != nil {
		finish(store.NotifyFailed, "the stored message could not be read")
		return
	}
	// The alert may have been suppressed while this was waiting.
	if it.AlertID != "" {
		if st, err := s.st.AlertStatus(ctx, it.AlertID); err == nil && st == store.AlertSuppressed {
			finish(store.NotifyDropped, "the alert was suppressed")
			return
		}
	}
	sctx, cancel := context.WithTimeout(ctx, smtpTimeout)
	defer cancel()
	err := s.send(sctx, c, m)
	if err == nil {
		finish(store.NotifySent, "")
		return
	}
	if ctx.Err() != nil {
		return // shutting down: it stays pending and goes out after the restart
	}
	attempts := it.Attempts + 1
	if attempts >= maxAttempts {
		finish(store.NotifyFailed, err.Error())
		s.log.Warn("notify: gave up on a message", "channel", c.Name, "kind", it.Kind, "attempts", attempts, "err", err)
		return
	}
	if rerr := s.st.RetryNotification(ctx, it.ID, err.Error(), s.now().Add(backoff(attempts))); rerr != nil {
		s.log.Warn("notify: update outbox", "err", rerr)
	}
	s.log.Info("notify: send failed, will retry", "channel", c.Name, "kind", it.Kind, "attempts", attempts, "err", err)
}

// ErrNoChannel is returned by Test for an unknown channel.
var ErrNoChannel = errors.New("no such channel")

// Test sends a test message to a stored channel right now, bypassing the outbox, and
// returns the result. The error is safe to show.
func (s *Service) Test(ctx context.Context, channelID string) error {
	set := s.Settings(ctx)
	c, ok := set.channel(channelID)
	if !ok {
		return ErrNoChannel
	}
	m := Message{
		Kind:  "test",
		Title: "HomeXDR test message",
		Body:  "If you can read this, the channel " + untrusted(c.Name, 100) + " works.",
		Link:  set.ConsoleURL,
	}
	sctx, cancel := context.WithTimeout(ctx, smtpTimeout)
	defer cancel()
	return s.send(sctx, c, m)
}

// Status is delivery status for the settings page.
type Status struct {
	*store.NotificationStats
	LastDigestAt *time.Time `json:"last_digest_at"`
	NextDigestAt *time.Time `json:"next_digest_at"`
}

// Status returns delivery status for the settings page.
func (s *Service) Status(ctx context.Context) (*Status, error) {
	st, err := s.st.GetNotificationStats(ctx, s.now())
	if err != nil {
		return nil, err
	}
	last, next := s.digestTimes(ctx, s.Settings(ctx))
	return &Status{NotificationStats: st, LastDigestAt: last, NextDigestAt: next}, nil
}
