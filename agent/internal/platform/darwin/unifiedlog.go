package darwin

import (
	"encoding/json"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/authparse"
)

// unifiedLogTime is the timestamp format of `log stream --style ndjson`.
const unifiedLogTime = "2006-01-02 15:04:05.000000-0700"

// parseUnifiedLogLine turns one `log stream --style ndjson` record into an auth message.
func parseUnifiedLogLine(line []byte) (authparse.Msg, bool) {
	var r struct {
		Timestamp        string `json:"timestamp"`
		EventMessage     string `json:"eventMessage"`
		ProcessImagePath string `json:"processImagePath"`
		ProcessID        int64  `json:"processID"`
		EventType        string `json:"eventType"`
	}
	if json.Unmarshal(line, &r) != nil || r.EventType != "logEvent" || r.EventMessage == "" {
		return authparse.Msg{}, false
	}
	m := authparse.Msg{App: baseName(r.ProcessImagePath), PID: r.ProcessID, Msg: r.EventMessage}
	if t, err := time.Parse(unifiedLogTime, r.Timestamp); err == nil {
		m.Time = t.UTC()
	}
	return m, true
}
