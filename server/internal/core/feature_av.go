package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/av"
	"github.com/Netdoodle/homexdr/server/internal/intel"
	"github.com/Netdoodle/homexdr/server/internal/store"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// avIssuer names the antivirus in the command history and audit log.
const avIssuer = "antivirus"

func (c *Core) initAV(ctx context.Context) {
	d := av.Deps{State: c.State, Log: c.Log, Lookup: c.avLookup, Fetch: c.avFetch, Detected: c.avDetected}
	if c.Cfg.ClamdAddr != "" {
		d.Clamd = &av.Clamd{Addr: c.Cfg.ClamdAddr}
	}
	if c.Cfg.YaraAddr != "" {
		d.Yara = av.NewYara(c.Cfg.YaraAddr)
	}
	c.AV = av.New(d)
	if err := c.AV.Load(ctx); err != nil {
		c.Log.Error("load antivirus settings", "err", err)
	}
}

func (c *Core) runAV(ctx context.Context) { c.AV.Run(ctx) }

// observeAV hands the antivirus every program start (and file write) that carries a
// SHA-256.
func (c *Core) observeAV(host *store.Host, evs []*event.Event) {
	if c.AV == nil || host == nil || host.Kind != store.HostEndpoint {
		return
	}
	for _, e := range evs {
		cand := av.Candidate{HostID: host.ID, Hostname: host.Hostname, Platform: host.OS.Platform}
		switch {
		case slices.Contains(e.Event.Category, event.CategoryProcess) && slices.Contains(e.Event.Type, event.TypeStart) &&
			e.Process != nil && e.Process.Hash != nil && e.Process.Hash.SHA256 != "":
			cand.Path, cand.SHA256, cand.PID, cand.EntityID = e.Process.Executable, e.Process.Hash.SHA256, e.Process.PID, e.Process.EntityID
		case slices.Contains(e.Event.Category, event.CategoryFile) && e.File != nil && e.File.Hash != nil && e.File.Hash.SHA256 != "" &&
			(slices.Contains(e.Event.Type, event.TypeCreation) || slices.Contains(e.Event.Type, event.TypeChange)):
			cand.Path, cand.SHA256 = e.File.Path, e.File.Hash.SHA256
		default:
			continue
		}
		c.AV.Observe(cand)
	}
}

// avLookup asks the threat intel sources about a hash.
func (c *Core) avLookup(ctx context.Context, sha256 string) (av.Reputation, error) {
	v, err := c.Intel.LookupAndWait(ctx, sha256, avIssuer)
	if err != nil {
		return av.Reputation{}, err
	}
	var rep av.Reputation
	best := -1
	for _, r := range v.Results {
		if r.Benign {
			rep.Known, rep.Source = true, r.Source
		}
		if r.Risk != nil && *r.Risk > best {
			best = *r.Risk
			if v.Summary.Verdict == intel.VerdictMalicious {
				rep.Name, rep.Source = r.Headline, r.Source
			}
		}
	}
	if v.Summary.Verdict == intel.VerdictMalicious {
		rep.Malicious, rep.Known = true, false
		if rep.Name == "" {
			rep.Name = "Known malware"
		}
	}
	return rep, nil
}

// avFetch uploads a file from its host with a file.get command and waits for it.
func (c *Core) avFetch(ctx context.Context, cand av.Candidate, maxBytes int64) (string, error) {
	h, err := c.State.GetHost(ctx, cand.HostID)
	if err != nil {
		return "", err
	}
	params, _ := json.Marshal(api.FileGetParams{Path: cand.Path, MaxBytes: maxBytes})
	rec, err := c.IssueCommand(ctx, h, api.CmdFileGet, params, avIssuer, "", 15*time.Minute)
	if err != nil {
		var ve *ValidationError
		if errors.Is(err, ErrNotAllowed) || errors.As(err, &ve) {
			return "", fmt.Errorf("%w: %v", av.ErrSkip, err)
		}
		return "", err
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-t.C:
		}
		cur, err := c.State.GetCommand(ctx, rec.ID)
		if err != nil {
			return "", err
		}
		if cur.UploadPath != "" {
			return cur.UploadPath, nil
		}
		if store.FinalStatus(cur.Status) {
			if cur.Status == api.StatusExpired {
				return "", errors.New("the host did not pick up the file request in time")
			}
			msg := cur.Error
			if msg == "" {
				msg = "no file was uploaded"
			}
			return "", fmt.Errorf("%w: %s", av.ErrSkip, msg)
		}
	}
}

// avDetected raises the alert and, when the antivirus is set to, stops the process tree
// and quarantines the file with signed commands, the same ones a person can send.
func (c *Core) avDetected(ctx context.Context, d av.Detection, set av.Settings) {
	action := "alert only: automatic response is off"
	if d.AlertOnly() {
		action = "alert only: YARA rules for hacking tools and suspicious traits are not stopped automatically"
	}
	if set.Action == av.ActionQuarantine && !d.AlertOnly() {
		var done, failed []string
		h, err := c.State.GetHost(ctx, d.HostID)
		if err != nil {
			failed = append(failed, "host lookup: "+err.Error())
		} else {
			if d.PID > 4 {
				p, _ := json.Marshal(api.KillParams{PID: d.PID, EntityID: d.EntityID, Tree: true})
				if _, err := c.IssueCommand(ctx, h, api.CmdProcessKill, p, avIssuer, "", time.Hour); err != nil {
					failed = append(failed, "stop process: "+err.Error())
				} else {
					done = append(done, "process stop sent")
				}
			}
			if d.Path != "" {
				p, _ := json.Marshal(api.FileHashParams{Path: d.Path})
				if _, err := c.IssueCommand(ctx, h, api.CmdFileQuarantine, p, avIssuer, "", 24*time.Hour); err != nil {
					failed = append(failed, "quarantine: "+err.Error())
				} else {
					done = append(done, "quarantine sent")
				}
			}
		}
		action = strings.Join(append(done, failed...), "; ")
	}
	sig := d.Signature
	if sig == "" {
		sig = "Malware"
	}
	f := Finding{
		RuleID:   "av:malware",
		Title:    "Malware detected: " + sig,
		Severity: store.SevCritical,
		Description: "HomeXDR's antivirus judged this program to be malware (" + avSourceLabel(d.Source) + "). " +
			"With automatic response on, the process and its children are stopped and the file is quarantined on the host; " +
			"a quarantined file can be restored from the host's page.",
		Tags:     []string{"attack.execution"},
		Entity:   d.SHA256,
		HostID:   d.HostID,
		Hostname: d.Hostname,
		Dataset:  "homexdr.av",
		Message:  fmt.Sprintf("%s: %s (%s)", sig, d.Path, action),
		Data: map[string]any{
			"av.sha256": d.SHA256, "av.path": d.Path, "av.signature": sig, "av.source": d.Source,
			"av.action": action, "av.pid": d.PID, "av.entity_id": d.EntityID,
		},
	}
	switch d.Source {
	case av.SourceYaraTool:
		f.RuleID, f.Title, f.Severity = "av:hacktool", "Hacking tool detected: "+sig, store.SevHigh
		f.Description = "A YARA rule for a hacking or remote-administration tool matched this program. Such tools are " +
			"used by attackers and by administrators alike, so it is not stopped automatically: if nobody here runs it on " +
			"purpose, stop it and quarantine the file from the host's page; if it is expected, add its hash to the allowlist."
	case av.SourceYaraSuspicious:
		f.RuleID, f.Title, f.Severity = "av:suspicious", "Suspicious program: "+sig, store.SevMedium
		f.Description = "A YARA rule for a generic suspicious trait (packing, evasion, unusual structure) matched this " +
			"program. That alone is not proof of malware, so it is not stopped automatically: check where it came from, " +
			"and add its hash to the allowlist when it is fine."
	}
	if err := c.RaiseFinding(ctx, f); err != nil {
		c.Log.Error("antivirus: raise alert", "err", err)
	}
	c.Log.Warn("antivirus: malware detected", "host", d.Hostname, "path", d.Path, "signature", sig, "source", d.Source, "action", action)
}

func avSourceLabel(s string) string {
	switch {
	case s == "clamav":
		return "ClamAV signature match"
	case s == av.SourceYara:
		return "YARA rule match"
	case s == "blocklist":
		return "the hash is on the antivirus blocklist"
	case strings.HasPrefix(s, "intel:"):
		return "known malware according to " + strings.TrimPrefix(s, "intel:")
	}
	return s
}
