//go:build linux

package linux

import (
	"github.com/Netdoodle/homexdr/agent/internal/authparse"
	"github.com/Netdoodle/homexdr/shared/event"
)

// authMsg is one auth log record; the parser is shared with macOS.
type authMsg = authparse.Msg

func parseAuth(m authMsg) *event.Event { return authparse.Parse(m) }
