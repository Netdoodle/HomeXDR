//go:build linux

package linux

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Netdoodle/homexdr/shared/event"
)

// authMsg is one auth log record, from journald or a syslog file.
type authMsg struct {
	App   string // syslog identifier: sshd, sudo, su, useradd, ...
	PID   int64
	Msg   string
	Time  time.Time
	Actor string // user that ran the program, when the source knows it (journald _UID)
}

var (
	reSSHAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	reSSHFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)`)
	reSSHInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)(?: port (\d+))?`)
	reSSHMaxAuth  = regexp.MustCompile(`^error: maximum authentication attempts exceeded for (invalid user )?(\S+) from (\S+) port (\d+)`)

	reSudo = regexp.MustCompile(`^\s*(\S+) : (.*)$`)

	reSuOK     = regexp.MustCompile(`^\(to (\S+)\) (\S+) on (\S+)`)
	reSuFailed = regexp.MustCompile(`^FAILED (?:SU|su) \(to (\S+)\) (\S+) on (\S+)`)
	reSuFail2  = regexp.MustCompile(`^FAILED su for (\S+) by (\S+)`)
	rePamFail  = regexp.MustCompile(`^pam_unix\((su|su-l):auth\): authentication failure;.*\bruser=(\S*).*\buser=(\S+)`)

	reNewUser    = regexp.MustCompile(`^new user: name=([^,]+), UID=(\d+), GID=(\d+)(?:, home=([^,]*))?(?:, shell=([^,]*))?`)
	reNewGroup   = regexp.MustCompile(`^new group: name=([^,]+), GID=(\d+)`)
	reAddToGroup = regexp.MustCompile(`^add '([^']+)' to group '([^']+)'`)
	reChangeUser = regexp.MustCompile(`^change user '([^']+)' (\S+) from '([^']*)' to '([^']*)'`)
	reLockUser   = regexp.MustCompile(`^(lock|unlock) user '([^']+)' password`)
	reDelUser    = regexp.MustCompile(`^delete user '([^']+)'`)
	reDelGroup   = regexp.MustCompile(`^group '([^']+)' removed$`)
	rePasswd     = regexp.MustCompile(`^pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (\S+)`)
)

func authEvent(m authMsg, cats, types []string, action, outcome string) *event.Event {
	e := &event.Event{
		Timestamp: m.Time,
		Event: event.Meta{
			Kind: event.KindEvent, Category: cats, Type: types, Action: action, Outcome: outcome,
			Module: event.ModuleAuthLog, Dataset: "linux.auth", Provider: m.App,
		},
		Message: m.Msg,
		Log:     &event.Log{AppName: m.App},
	}
	if m.PID > 0 {
		e.Process = &event.Process{PID: m.PID, Name: m.App}
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	return e
}

func withSource(e *event.Event, ip, port string) {
	p, _ := strconv.Atoi(port)
	e.Source = &event.Endpoint{IP: ip, Port: p}
}

// parseAuth recognizes sshd, sudo, su and account-management messages. It returns nil
// for anything else.
func parseAuth(m authMsg) *event.Event {
	msg := strings.TrimSpace(m.Msg)
	m.Msg = msg
	authn := []string{event.CategoryAuthentication}
	start := []string{event.TypeStart}
	iam := []string{event.CategoryIAM}
	app := strings.ToLower(m.App)
	switch {
	case app == "sshd" || strings.HasPrefix(app, "sshd-") || app == "sshd-session":
		if g := reSSHAccepted.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, append(authn, event.CategorySession), start, "ssh_login", event.OutcomeSuccess)
			e.User = &event.User{Name: g[2]}
			withSource(e, g[3], g[4])
			e.Data = map[string]any{"auth_method": g[1]}
			return e
		}
		if g := reSSHFailed.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, authn, start, "ssh_login", event.OutcomeFailure)
			e.User = &event.User{Name: g[3]}
			withSource(e, g[4], g[5])
			e.Data = map[string]any{"auth_method": g[1], "invalid_user": g[2] != ""}
			return e
		}
		if g := reSSHMaxAuth.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, authn, start, "ssh_login", event.OutcomeFailure)
			e.User = &event.User{Name: g[2]}
			withSource(e, g[3], g[4])
			e.Data = map[string]any{"reason": "max_auth_tries", "invalid_user": g[1] != ""}
			return e
		}
		if g := reSSHInvalid.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, authn, start, "ssh_invalid_user", event.OutcomeFailure)
			e.User = &event.User{Name: g[1]}
			withSource(e, g[2], g[3])
			return e
		}
	case app == "sudo":
		g := reSudo.FindStringSubmatch(msg)
		if g == nil || strings.HasPrefix(msg, "pam_") {
			return nil
		}
		fields := map[string]string{}
		var notes []string
		for _, part := range strings.Split(g[2], " ; ") {
			if k, v, ok := strings.Cut(part, "="); ok && k == strings.ToUpper(k) && !strings.Contains(k, " ") {
				fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
			} else {
				notes = append(notes, strings.TrimSpace(part))
			}
		}
		if fields["COMMAND"] == "" && fields["USER"] == "" {
			return nil
		}
		outcome := event.OutcomeSuccess
		if len(notes) > 0 {
			outcome = event.OutcomeFailure // "3 incorrect password attempts", "user NOT in sudoers", ...
		}
		e := authEvent(m, authn, start, "sudo", outcome)
		target := fields["USER"]
		if target == "" {
			target = "root"
		}
		e.User = &event.User{Name: g[1], Target: &event.User{Name: target}}
		data := map[string]any{"command": fields["COMMAND"], "pwd": fields["PWD"]}
		if t := fields["TTY"]; t != "" {
			data["tty"] = t
		}
		if len(notes) > 0 {
			data["reason"] = strings.Join(notes, "; ")
		}
		e.Data = data
		return e
	case app == "su":
		if g := reSuOK.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, authn, start, "su", event.OutcomeSuccess)
			e.User = &event.User{Name: g[2], Target: &event.User{Name: g[1]}}
			e.Data = map[string]any{"tty": g[3]}
			return e
		}
		if g := reSuFailed.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, authn, start, "su", event.OutcomeFailure)
			e.User = &event.User{Name: g[2], Target: &event.User{Name: g[1]}}
			return e
		}
		if g := reSuFail2.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, authn, start, "su", event.OutcomeFailure)
			e.User = &event.User{Name: g[2], Target: &event.User{Name: g[1]}}
			return e
		}
		if g := rePamFail.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, authn, start, "su", event.OutcomeFailure)
			e.User = &event.User{Name: g[2], Target: &event.User{Name: g[3]}}
			return e
		}
	case app == "useradd" || app == "adduser":
		if g := reNewUser.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, iam, []string{event.TypeUser, event.TypeCreation}, "user_created", event.OutcomeSuccess)
			e.User = actor(m, &event.User{Name: g[1], ID: g[2]})
			e.Data = map[string]any{"uid": g[2], "gid": g[3], "home": g[4], "shell": g[5]}
			return e
		}
		fallthrough
	case app == "groupadd" || app == "addgroup":
		if g := reNewGroup.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, iam, []string{event.TypeGroup, event.TypeCreation}, "group_created", event.OutcomeSuccess)
			e.User = actor(m, nil)
			e.Data = map[string]any{"group": g[1], "gid": g[2]}
			return e
		}
	case app == "usermod" || app == "gpasswd":
		if g := reAddToGroup.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, iam, []string{event.TypeGroup, event.TypeChange}, "group_member_added", event.OutcomeSuccess)
			e.User = actor(m, &event.User{Name: g[1]})
			e.Data = map[string]any{"group": g[2]}
			return e
		}
		if g := reChangeUser.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, iam, []string{event.TypeUser, event.TypeChange}, "user_changed", event.OutcomeSuccess)
			e.User = actor(m, &event.User{Name: g[1]})
			e.Data = map[string]any{"attribute": g[2], "old": g[3], "new": g[4]}
			return e
		}
		if g := reLockUser.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, iam, []string{event.TypeUser, event.TypeChange}, "user_"+g[1]+"ed", event.OutcomeSuccess)
			e.User = actor(m, &event.User{Name: g[2]})
			return e
		}
	case app == "userdel" || app == "deluser":
		if g := reDelUser.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, iam, []string{event.TypeUser, event.TypeDeletion}, "user_deleted", event.OutcomeSuccess)
			e.User = actor(m, &event.User{Name: g[1]})
			return e
		}
		fallthrough
	case app == "groupdel" || app == "delgroup":
		if g := reDelGroup.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, iam, []string{event.TypeGroup, event.TypeDeletion}, "group_deleted", event.OutcomeSuccess)
			e.User = actor(m, nil)
			e.Data = map[string]any{"group": g[1]}
			return e
		}
	case app == "passwd" || app == "chpasswd":
		if g := rePasswd.FindStringSubmatch(msg); g != nil {
			e := authEvent(m, iam, []string{event.TypeUser, event.TypeChange}, "password_changed", event.OutcomeSuccess)
			e.User = actor(m, &event.User{Name: g[1]})
			return e
		}
	}
	return nil
}

// actor returns user.name = the account that ran the tool (if known) and user.target =
// the account acted upon.
func actor(m authMsg, target *event.User) *event.User {
	u := &event.User{Name: m.Actor, Target: target}
	if u.Name == "" && target == nil {
		return nil
	}
	return u
}
