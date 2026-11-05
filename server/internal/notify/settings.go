package notify

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"
	_ "time/tzdata" // the digest's time zone must load in a container without tzdata

	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/event"
)

// Channel kinds.
const (
	KindNtfy    = "ntfy"
	KindDiscord = "discord"
	KindEmail   = "email"
	KindWebhook = "webhook"
)

// Routes: what happens to a new alert.
const (
	RouteNow    = "now"
	RouteDigest = "digest"
	RouteLog    = "log"
)

const settingsKey = "notify_settings"

// Channel is one place to send messages. URL, Token and Password are secrets: write-only
// through the API, and never logged.
type Channel struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	// URL is the ntfy topic URL, the Discord webhook URL or the generic webhook URL.
	URL string `json:"url,omitempty"`
	// Token is an optional bearer token for ntfy or the generic webhook.
	Token string `json:"token,omitempty"`

	SMTPHost string `json:"smtp_host,omitempty"`
	SMTPPort int    `json:"smtp_port,omitempty"`
	SMTPUser string `json:"smtp_user,omitempty"`
	Password string `json:"password,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"` // comma-separated
}

// RuleRoute overrides the route for rule IDs starting with Prefix. The longest match wins.
type RuleRoute struct {
	Prefix string `json:"prefix"`
	Route  string `json:"route"`
}

// Settings configure notifications. With no enabled channel, nothing is sent or queued.
type Settings struct {
	Channels []Channel `json:"channels"`
	// SeverityRoutes maps a severity to a route.
	SeverityRoutes map[string]string `json:"severity_routes"`
	RuleRoutes     []RuleRoute       `json:"rule_routes"`
	// RatePerHour caps immediate alerts. The rest go to the digest.
	RatePerHour int `json:"rate_per_hour"`
	// DigestEnabled, DigestTime ("07:00") and Timezone (IANA name; empty is the server's
	// zone) schedule the daily digest.
	DigestEnabled bool   `json:"digest_enabled"`
	DigestTime    string `json:"digest_time"`
	Timezone      string `json:"timezone"`
	// Heartbeat sends the digest even on a day with nothing to say.
	Heartbeat bool `json:"heartbeat"`
	// ConsoleURL is the base of links back to the console; empty leaves links out.
	ConsoleURL string `json:"console_url"`
}

// DefaultSettings: no channels, so off. Critical and high alert now, medium goes to the
// digest, low and informational are only logged.
func DefaultSettings() Settings {
	return Settings{
		Channels: []Channel{},
		SeverityRoutes: map[string]string{
			store.SevCritical: RouteNow, store.SevHigh: RouteNow, store.SevMedium: RouteDigest,
			store.SevLow: RouteLog, store.SevInformational: RouteLog,
		},
		RuleRoutes:    []RuleRoute{},
		RatePerHour:   10,
		DigestEnabled: true,
		DigestTime:    "07:00",
	}
}

func validRoute(r string) bool { return r == RouteNow || r == RouteDigest || r == RouteLog }

// Route returns what should happen to a new alert with this severity and rule.
func (s Settings) Route(severity, ruleID string) string {
	best, route := -1, ""
	for _, rr := range s.RuleRoutes {
		if strings.HasPrefix(ruleID, rr.Prefix) && len(rr.Prefix) > best {
			best, route = len(rr.Prefix), rr.Route
		}
	}
	if route != "" {
		return route
	}
	if r, ok := s.SeverityRoutes[severity]; ok {
		return r
	}
	return RouteLog
}

func (s Settings) enabledChannels() []Channel {
	var out []Channel
	for _, c := range s.Channels {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out
}

func (s Settings) channel(id string) (Channel, bool) {
	for _, c := range s.Channels {
		if c.ID == id {
			return c, true
		}
	}
	return Channel{}, false
}

// location is the digest's time zone.
func (s Settings) location() *time.Location {
	if s.Timezone != "" {
		if l, err := time.LoadLocation(s.Timezone); err == nil {
			return l
		}
	}
	return time.Local
}

// InputError is a settings value the owner has to fix.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func inputErr(format string, a ...any) error { return &InputError{Msg: fmt.Sprintf(format, a...)} }

func validateHTTPURL(raw, what string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return inputErr("%s must be an http(s) URL", what)
	}
	return nil
}

func (c *Channel) validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		c.Name = c.Kind
	}
	if len(c.Name) > 100 {
		return inputErr("channel name is too long")
	}
	switch c.Kind {
	case KindNtfy, KindDiscord, KindWebhook:
		if c.URL == "" {
			return inputErr("channel %q needs a URL", c.Name)
		}
		if err := validateHTTPURL(c.URL, "the URL of channel "+c.Name); err != nil {
			return err
		}
		if c.Kind == KindDiscord && !strings.HasPrefix(c.URL, "https://") {
			return inputErr("a Discord webhook URL starts with https://")
		}
	case KindEmail:
		c.SMTPHost = strings.TrimSpace(c.SMTPHost)
		if c.SMTPHost == "" || strings.ContainsAny(c.SMTPHost, " /:") {
			return inputErr("channel %q needs an SMTP server name", c.Name)
		}
		if c.SMTPPort == 0 {
			c.SMTPPort = 587
		}
		if c.SMTPPort < 1 || c.SMTPPort > 65535 {
			return inputErr("channel %q has a bad SMTP port", c.Name)
		}
		if _, err := mail.ParseAddress(c.From); err != nil {
			return inputErr("channel %q needs a valid From address", c.Name)
		}
		if _, err := mail.ParseAddressList(c.To); err != nil {
			return inputErr("channel %q needs a valid To address", c.Name)
		}
	default:
		return inputErr("unknown channel kind %q", c.Kind)
	}
	return nil
}

// Validate checks and normalizes settings.
func (s *Settings) Validate() error {
	seen := map[string]bool{}
	for i := range s.Channels {
		c := &s.Channels[i]
		if c.ID == "" {
			c.ID = event.NewID()
		}
		if seen[c.ID] {
			return inputErr("two channels have the same ID")
		}
		seen[c.ID] = true
		if err := c.validate(); err != nil {
			return err
		}
	}
	for sev, r := range s.SeverityRoutes {
		if !validRoute(r) {
			return inputErr("the route for %s must be now, digest or log", sev)
		}
	}
	for i := range s.RuleRoutes {
		rr := &s.RuleRoutes[i]
		rr.Prefix = strings.TrimSpace(rr.Prefix)
		if rr.Prefix == "" {
			return inputErr("a rule route needs a rule ID prefix")
		}
		if !validRoute(rr.Route) {
			return inputErr("the route for %s must be now, digest or log", rr.Prefix)
		}
	}
	if s.RatePerHour < 1 || s.RatePerHour > 1000 {
		return inputErr("the rate cap must be between 1 and 1000 alerts an hour")
	}
	if _, err := time.Parse("15:04", s.DigestTime); err != nil {
		return inputErr("the digest time must look like 07:00")
	}
	s.Timezone = strings.TrimSpace(s.Timezone)
	if s.Timezone != "" {
		if _, err := time.LoadLocation(s.Timezone); err != nil {
			return inputErr("unknown time zone %q; use a name like Europe/Prague", s.Timezone)
		}
	}
	s.ConsoleURL = strings.TrimRight(strings.TrimSpace(s.ConsoleURL), "/")
	if s.ConsoleURL != "" {
		if err := validateHTTPURL(s.ConsoleURL, "the console URL"); err != nil {
			return err
		}
	}
	return nil
}

// ChannelView is a channel as the API shows it: whether secrets are set, never what they are.
type ChannelView struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	URLSet      bool   `json:"url_set"`
	URLHost     string `json:"url_host,omitempty"`
	TokenSet    bool   `json:"token_set"`
	PasswordSet bool   `json:"password_set"`
	SMTPHost    string `json:"smtp_host,omitempty"`
	SMTPPort    int    `json:"smtp_port,omitempty"`
	SMTPUser    string `json:"smtp_user,omitempty"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
}

// SettingsView is settings as the API shows them.
type SettingsView struct {
	Settings
	Channels []ChannelView `json:"channels"`
}

// View returns the settings without secrets.
func (s Settings) View() SettingsView {
	v := SettingsView{Settings: s, Channels: []ChannelView{}}
	for _, c := range s.Channels {
		cv := ChannelView{ID: c.ID, Kind: c.Kind, Name: c.Name, Enabled: c.Enabled, URLSet: c.URL != "", TokenSet: c.Token != "",
			PasswordSet: c.Password != "", SMTPHost: c.SMTPHost, SMTPPort: c.SMTPPort, SMTPUser: c.SMTPUser, From: c.From, To: c.To}
		if u, err := url.Parse(c.URL); err == nil {
			cv.URLHost = u.Host // the path of these URLs is the secret; the host tells channels apart
		}
		v.Channels = append(v.Channels, cv)
	}
	return v
}

// ChannelUpdate is a channel as the API takes it. A blank secret keeps the stored one;
// ClearToken and ClearPassword remove them.
type ChannelUpdate struct {
	Channel
	ClearToken    bool `json:"clear_token"`
	ClearPassword bool `json:"clear_password"`
}

// SettingsUpdate replaces the settings. Channels left out are removed.
type SettingsUpdate struct {
	Settings
	Channels []ChannelUpdate `json:"channels"`
}

// Apply merges an update over the current settings, keeping secrets it does not change.
func (u SettingsUpdate) Apply(cur Settings) Settings {
	out := u.Settings
	if out.SeverityRoutes == nil {
		out.SeverityRoutes = DefaultSettings().SeverityRoutes
	}
	if out.RuleRoutes == nil {
		out.RuleRoutes = []RuleRoute{}
	}
	out.Channels = make([]Channel, 0, len(u.Channels))
	for _, cu := range u.Channels {
		c := cu.Channel
		c.URL, c.Token, c.Password = strings.TrimSpace(c.URL), strings.TrimSpace(c.Token), strings.TrimSpace(c.Password)
		if old, ok := cur.channel(c.ID); ok && old.Kind == c.Kind {
			if c.URL == "" {
				c.URL = old.URL
			}
			if c.Token == "" && !cu.ClearToken {
				c.Token = old.Token
			}
			if c.Password == "" && !cu.ClearPassword {
				c.Password = old.Password
			}
		}
		out.Channels = append(out.Channels, c)
	}
	return out
}

// Settings returns the stored settings (defaults when none are stored).
func (s *Service) Settings(ctx context.Context) Settings {
	set := DefaultSettings()
	if err := s.st.GetKV(ctx, settingsKey, &set); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Warn("notify: read settings", "err", err)
	}
	if set.Channels == nil {
		set.Channels = []Channel{}
	}
	if set.RuleRoutes == nil {
		set.RuleRoutes = []RuleRoute{}
	}
	return set
}

// SaveSettings validates and stores an update, and returns the result.
func (s *Service) SaveSettings(ctx context.Context, u SettingsUpdate) (Settings, error) {
	set := u.Apply(s.Settings(ctx))
	if err := set.Validate(); err != nil {
		return set, err
	}
	if err := s.st.SetKV(ctx, settingsKey, set); err != nil {
		return set, err
	}
	s.poke()
	return set, nil
}
