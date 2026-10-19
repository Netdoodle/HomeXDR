// Package version holds build metadata, set with -ldflags at build time:
//
//	-X github.com/Netdoodle/homexdr/shared/version.Version=v0.1.0
//	-X github.com/Netdoodle/homexdr/shared/version.Commit=abc1234
package version

var (
	Version = "dev"
	Commit  = "unknown"
)

// String returns "Version (Commit)".
func String() string {
	return Version + " (" + Commit + ")"
}
