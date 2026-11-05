package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Message is one thing to tell the owner. Title and Body are already clean and defanged.
// Link is the console's own URL, which is the one thing left clickable.
type Message struct {
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	Body     string `json:"body"`
	Severity string `json:"severity,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
	AlertID  string `json:"alert_id,omitempty"`
	Link     string `json:"link,omitempty"`
}

const (
	userAgent    = "HomeXDR"
	sendTimeout  = 15 * time.Second
	smtpTimeout  = 30 * time.Second
	maxRespBytes = 4 << 10

	// Message size limits of the services.
	discordLimit = 1950 // Discord's limit is 2000, and shortenBody adds a line
	ntfyLimit    = 3800
)

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: sendTimeout,
		// The configured URL is the destination. Do not follow it anywhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// send delivers a message to a channel. Its errors never contain the channel's secrets.
func (s *Service) send(ctx context.Context, c Channel, m Message) error {
	var err error
	switch c.Kind {
	case KindNtfy:
		err = s.sendNtfy(ctx, c, m)
	case KindDiscord:
		err = s.sendDiscord(ctx, c, m)
	case KindWebhook:
		err = s.sendWebhook(ctx, c, m)
	case KindEmail:
		err = s.sendEmail(ctx, c, m)
	default:
		err = fmt.Errorf("unknown channel kind %q", c.Kind)
	}
	if err != nil {
		return errors.New(redact(err, c))
	}
	return nil
}

// redact turns an error into text with no trace of the channel's secrets. An http.Client
// error quotes the whole URL, and in these URLs the path is the secret.
func redact(err error, c Channel) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	for _, secret := range []string{c.URL, c.Token, c.Password} {
		if secret != "" {
			msg = strings.ReplaceAll(msg, secret, "[secret]")
		}
	}
	if u, perr := url.Parse(c.URL); perr == nil && len(u.Path) > 1 {
		msg = strings.ReplaceAll(msg, u.Path, "[secret]")
	}
	return shorten(msg, 500)
}

func (s *Service) post(ctx context.Context, rawURL string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("the URL is not valid")
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxRespBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("the service answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// ntfyPriority maps a message to ntfy's 1-5 scale.
func ntfyPriority(m Message) string {
	switch m.Severity {
	case "critical":
		return "5"
	case "high":
		return "4"
	}
	return "3"
}

func (s *Service) sendNtfy(ctx context.Context, c Channel, m Message) error {
	body := shortenBody(m.Body, ntfyLimit)
	if m.Link != "" {
		body += "\n" + m.Link
	}
	headers := map[string]string{
		"Title":        mime.QEncoding.Encode("utf-8", shorten(m.Title, 200)),
		"Priority":     ntfyPriority(m),
		"Content-Type": "text/plain; charset=utf-8",
	}
	if m.Link != "" {
		headers["Click"] = m.Link
	}
	if c.Token != "" {
		headers["Authorization"] = "Bearer " + c.Token
	}
	return s.post(ctx, c.URL, []byte(body), headers)
}

func (s *Service) sendDiscord(ctx context.Context, c Channel, m Message) error {
	head := "**" + discordEscape(shorten(m.Title, 200)) + "**\n"
	tail := ""
	if m.Link != "" {
		tail = "\n<" + m.Link + ">" // the brackets stop Discord from unfurling it
	}
	// Escaping makes text longer, so measure after it. The link always fits.
	content := head + shortenBody(discordEscape(m.Body), discordLimit-len(head)-len(tail)) + tail
	b, err := json.Marshal(map[string]any{
		"content":          content,
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
	if err != nil {
		return err
	}
	return s.post(ctx, c.URL, b, map[string]string{"Content-Type": "application/json"})
}

func (s *Service) sendWebhook(ctx context.Context, c Channel, m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	headers := map[string]string{"Content-Type": "application/json"}
	if c.Token != "" {
		headers["Authorization"] = "Bearer " + c.Token
	}
	return s.post(ctx, c.URL, b, headers)
}

// shortenBody cuts a long message and says so.
func shortenBody(body string, n int) string {
	if len(body) <= n {
		return body
	}
	return shorten(body, n) + "\n(cut short, see the console)"
}

func (s *Service) tlsConfig(host string) *tls.Config {
	if s.smtpTLS != nil {
		return s.smtpTLS(host)
	}
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
}

// sendEmail sends through SMTP over STARTTLS. A server that does not offer STARTTLS is
// refused: alert details and the password never travel in the clear.
func (s *Service) sendEmail(ctx context.Context, c Channel, m Message) error {
	addr := net.JoinHostPort(c.SMTPHost, strconv.Itoa(c.SMTPPort))
	deadline := time.Now().Add(smtpTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	d := net.Dialer{Deadline: deadline}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, c.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return errors.New("the mail server does not offer STARTTLS, so nothing was sent")
	}
	if err := client.StartTLS(s.tlsConfig(c.SMTPHost)); err != nil {
		return err
	}
	if c.SMTPUser != "" {
		if err := client.Auth(smtp.PlainAuth("", c.SMTPUser, c.Password, c.SMTPHost)); err != nil {
			return err
		}
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return errors.New("the From address is not valid")
	}
	to, err := mail.ParseAddressList(c.To)
	if err != nil {
		return errors.New("the To address is not valid")
	}
	if err := client.Mail(from.Address); err != nil {
		return err
	}
	for _, a := range to {
		if err := client.Rcpt(a.Address); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(buildEmail(from, to, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// buildEmail builds a plain text message. The subject is encoded and cannot carry extra
// headers, because clean() has already taken out line breaks.
func buildEmail(from *mail.Address, to []*mail.Address, m Message) []byte {
	var b bytes.Buffer
	names := make([]string, len(to))
	for i, a := range to {
		names[i] = a.String()
	}
	fmt.Fprintf(&b, "From: %s\r\n", from.String())
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(names, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", clean(m.Title, false)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	text := m.Body
	if m.Link != "" {
		text += "\n\n" + m.Link
	}
	qp.Write([]byte(strings.ReplaceAll(text, "\n", "\r\n")))
	qp.Close()
	return b.Bytes()
}
