//go:build windows

package windows

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Only LocalSystem (the service account) and the Administrators group may open the
// agent's config and data. "P" makes the DACL protected, so nothing is inherited from
// C:\ProgramData (which lets every user read). Directory ACEs are inherited by
// everything created inside, and SetNamedSecurityInfo pushes them down to what
// already exists.
const (
	dirSDDL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	fileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

// ProtectPath implements platform.PathProtector.
func (*Platform) ProtectPath(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	sddl := fileSDDL
	if fi.IsDir() {
		sddl = dirSDDL
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("set ACL on %s: %w", path, err)
	}
	return nil
}
