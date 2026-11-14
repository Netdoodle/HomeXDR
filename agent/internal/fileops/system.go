package fileops

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Quarantine refuses operating-system files, so that one command (from a stolen console
// account, or a mistake) cannot leave a host unbootable or without its core tools. The
// check runs on the agent, so the server cannot skip it. Malware that hides among system
// files can still be stopped (process.kill, App Control) and removed by hand.
//
// Each list holds protected trees and, inside them, places malware commonly uses for
// persistence that quarantine may still clean up (temp folders, cron and systemd units,
// /etc/ld.so.preload, /usr/local). Paths are compared with forward slashes, and without
// case on Windows and macOS.

type systemTrees struct {
	protected []string
	allowed   []string
	fold      bool
}

func systemTreesFor(goos, systemRoot string) systemTrees {
	switch goos {
	case "windows":
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		root := filepath.ToSlash(systemRoot)
		drive := root[:min(2, len(root))] // "C:"
		return systemTrees{
			protected: []string{root, drive + "/bootmgr", drive + "/BOOTNXT", drive + "/EFI", drive + "/Boot"},
			allowed:   []string{root + "/Temp"},
			fold:      true,
		}
	case "darwin":
		return systemTrees{
			protected: []string{"/System", "/bin", "/sbin", "/usr", "/etc", "/private/etc", "/Library/Apple"},
			allowed:   []string{"/usr/local"},
			fold:      true,
		}
	default: // Linux and other Unixes
		return systemTrees{
			protected: []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/boot", "/etc"},
			allowed: []string{
				"/usr/local",
				"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
				"/etc/systemd/system", "/etc/init.d", "/etc/rc.local", "/etc/profile.d", "/etc/xdg/autostart",
				"/etc/ld.so.preload",
			},
		}
	}
}

func (t systemTrees) norm(p string) string {
	p = filepath.ToSlash(p)
	if t.fold {
		p = strings.ToLower(p)
	}
	return strings.TrimSuffix(p, "/")
}

func (t systemTrees) under(p, root string) bool {
	p, root = t.norm(p), t.norm(root)
	return p == root || strings.HasPrefix(p, root+"/")
}

// isSystem reports whether p (absolute and clean) is in a protected tree and not in one
// of its allowed places.
func (t systemTrees) isSystem(p string) bool {
	for _, a := range t.allowed {
		if t.under(p, a) {
			return false
		}
	}
	for _, r := range t.protected {
		if t.under(p, r) {
			return true
		}
	}
	return false
}

// localSystemTrees is the list for this host.
func localSystemTrees() systemTrees {
	return systemTreesFor(runtime.GOOS, os.Getenv("SystemRoot"))
}

// realPath resolves symbolic links in p's directory (the file itself is checked with
// Lstat), so a linked directory cannot be used to reach a protected file. It returns p
// when the directory cannot be resolved.
func realPath(p string) string {
	d, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return p
	}
	return filepath.Join(d, filepath.Base(p))
}

// remoteOrDevicePath reports Windows paths that are not plain local paths: UNC shares
// (including \\localhost\C$) and \\?\ or \\.\ device paths.
func remoteOrDevicePath(p string) bool {
	return runtime.GOOS == "windows" && (strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`))
}
