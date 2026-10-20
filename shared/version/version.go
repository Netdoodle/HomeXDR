// Package version holds build metadata, set with -ldflags at build time:
//
//	-X github.com/Netdoodle/homexdr/shared/version.Version=v0.1.0
//	-X github.com/Netdoodle/homexdr/shared/version.Commit=abc1234
//	-X github.com/Netdoodle/homexdr/shared/version.CommitTime=1792470533
package version

import "strconv"

var (
	Version = "dev"
	Commit  = "unknown"
	// CommitTime is the commit's Unix time in seconds. Agents compare it with an offered
	// release so they never "update" to an older build.
	CommitTime = "0"
)

// String returns "Version (Commit)".
func String() string {
	return Version + " (" + Commit + ")"
}

// CommitUnix returns CommitTime as a number, 0 when it is unset or invalid.
func CommitUnix() int64 {
	n, err := strconv.ParseInt(CommitTime, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
