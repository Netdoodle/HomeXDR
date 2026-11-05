package core

import (
	"context"
	"strings"
)

func init() {
	RegisterDoctorCheck(DoctorCheck{"lists", "Offline lists", checkLists})
}

// checkLists reports enabled lists that have failed or never been downloaded.
func checkLists(_ context.Context, c *Core) CheckResult {
	var failed, missing []string
	on := 0
	for _, v := range c.Health.Lists.Views() {
		if !v.Enabled {
			continue
		}
		on++
		switch {
		case v.Error != "":
			failed = append(failed, v.Name+": "+v.Error)
		case v.LastUpdate == nil:
			missing = append(missing, v.Name)
		}
	}
	switch {
	case on == 0:
		return checkSkip("All offline lists are turned off.")
	case len(failed) > 0:
		return checkWarn("Open Settings > Offline lists. A blocked host needs allowing on your firewall's DNS blocklist, or turn that list off. The last good copy stays in use.", "%s", strings.Join(failed, " "))
	case len(missing) > 0:
		return checkWarn("These download by themselves within a few minutes of the server starting. If they do not, open Settings > Offline lists.", "Not downloaded yet: %s.", strings.Join(missing, ", "))
	}
	return checkOK("%d lists up to date.", on)
}
