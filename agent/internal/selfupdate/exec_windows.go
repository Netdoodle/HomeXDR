//go:build windows

package selfupdate

import "errors"

// Exec is not supported on Windows (see Supported).
func Exec(string) error {
	return errors.New("self-update restart is not supported on Windows; restart the HomeXDR Agent service")
}
