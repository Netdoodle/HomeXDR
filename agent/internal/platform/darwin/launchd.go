package darwin

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

// launchd job of the agent.
const (
	serviceLabel   = "com.homexdr.agent"
	servicePlist   = "/Library/LaunchDaemons/" + serviceLabel + ".plist"
	serviceLogDir  = "/Library/Logs/HomeXDR"
	serviceLogFile = serviceLogDir + "/agent.log"
	// newsyslogConf rotates the log: 5 files of 10 MiB, compressed.
	newsyslogConf = "/etc/newsyslog.d/homexdr.conf"
)

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// launchdPlist is the job definition: `<exe> run` as root at boot, restarted whenever it
// exits, with stdout and stderr appended to the log file.
func launchdPlist(exe string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Standard</string>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, serviceLabel, xmlEscape(exe), serviceLogFile, serviceLogFile)
}

// newsyslogLine rotates the agent log.
const newsyslogLine = "# HomeXDR agent log rotation (installed by homexdr-agent install)\n" +
	"# logfilename                         mode count size(KB) when flags\n" +
	serviceLogFile + "    640  5     10240    *    J\n"
