//go:build windows

package windows

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/Netdoodle/homexdr/shared/event"
	"golang.org/x/sys/windows"
)

// What the process sensor reads from live processes: the snapshot at startup, the real
// creation time behind entity IDs, and the details Security event 4688 lacks.

// detailFlags select what procSource.open reads besides the creation time.
type detailFlags uint8

const (
	// wantDetails reads the image path, command line, user SID and session.
	wantDetails detailFlags = 1 << iota
	// wantCwd also reads the current directory from the process parameters, which
	// needs PROCESS_VM_READ.
	wantCwd
)

// liveProc is what could be read from a process object.
type liveProc struct {
	Created          windows.Filetime
	Executable       string
	CommandLine      string
	WorkingDirectory string
	UserSID          string
	SessionID        int64
	HasSession       bool
}

// createdAt returns the creation time as a time.Time.
func (p *liveProc) createdAt() time.Time { return filetimeToTime(p.Created) }

// procPair is one entry of a process list.
type procPair struct {
	PID, PPID int64
	Name      string
}

// procSource reads live processes. The sensor uses winProcs; tests use a fake.
type procSource interface {
	// list returns the running processes.
	list() ([]procPair, error)
	// open returns the process object with this PID, if one exists (running, or exited
	// but still referenced), with its creation time and the details asked for.
	open(pid int64, want detailFlags) (*liveProc, bool)
}

// filetimeKey returns a FILETIME as the uint64 entity ID start key.
func filetimeKey(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// filetimeEpochDelta is the number of 100 ns intervals from 1601-01-01 to 1970-01-01.
const filetimeEpochDelta = 116444736000000000

// timeToFiletimeKey converts a time to the FILETIME start key.
func timeToFiletimeKey(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano()/100 + filetimeEpochDelta)
}

func filetimeToTime(ft windows.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds()).UTC()
}

// winProcs reads live Windows processes.
type winProcs struct {
	// readCwd is false when the agent runs under WOW64, where it cannot read the
	// 64-bit process parameters.
	readCwd bool
}

func newWinProcs() *winProcs {
	w := &winProcs{readCwd: true}
	var wow bool
	if windows.IsWow64Process(windows.CurrentProcess(), &wow) == nil && wow {
		w.readCwd = false
	}
	return w
}

func (*winProcs) list() ([]procPair, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []procPair
	err = windows.Process32First(snap, &pe)
	for err == nil {
		out = append(out, procPair{PID: int64(pe.ProcessID), PPID: int64(pe.ParentProcessID), Name: windows.UTF16ToString(pe.ExeFile[:])})
		err = windows.Process32Next(snap, &pe)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return out, fmt.Errorf("process snapshot: %w", err)
	}
	return out, nil
}

func (w *winProcs) open(pid int64, want detailFlags) (*liveProc, bool) {
	if pid <= 0 || pid > 0xFFFFFFFF {
		return nil, false
	}
	var h windows.Handle
	var err error
	cwd := want&wantCwd != 0 && w.readCwd
	if cwd {
		h, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
		if err != nil {
			cwd = false
		}
	}
	if h == 0 {
		h, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return nil, false
		}
	}
	defer windows.CloseHandle(h)
	p := &liveProc{}
	var exit, kern, user windows.Filetime
	if windows.GetProcessTimes(h, &p.Created, &exit, &kern, &user) != nil || filetimeKey(p.Created) == 0 {
		return nil, false
	}
	if want&(wantDetails|wantCwd) != 0 {
		p.Executable = processImagePath(h)
		p.CommandLine = processCommandLine(h)
		p.UserSID = processUserSID(h)
		var sess uint32
		if windows.ProcessIdToSessionId(uint32(pid), &sess) == nil {
			p.SessionID, p.HasSession = int64(sess), true
		}
	}
	if cwd {
		p.WorkingDirectory = processCurrentDirectory(h)
	}
	return p, true
}

func processImagePath(h windows.Handle) string {
	for _, size := range []uint32{512, windows.MAX_LONG_PATH} {
		buf := make([]uint16, size)
		n := size
		if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err == nil {
			return windows.UTF16ToString(buf[:n])
		} else if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return ""
		}
	}
	return ""
}

// remoteUnicodeString is UNICODE_STRING with the buffer address as an integer, so
// addresses from another process never sit in a Go pointer.
type remoteUnicodeString struct {
	Length, MaximumLength uint16
	Buffer                uintptr
}

// processCommandLine reads the command line with ProcessCommandLineInformation, which
// needs only PROCESS_QUERY_LIMITED_INFORMATION (Windows 8.1 and later).
func processCommandLine(h windows.Handle) string {
	size := uint32(2048)
	for range 3 {
		buf := make([]byte, size)
		var ret uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), size, &ret)
		if err == nil {
			us := (*remoteUnicodeString)(unsafe.Pointer(&buf[0]))
			if us.Length == 0 || us.Buffer == 0 {
				return ""
			}
			off := us.Buffer - uintptr(unsafe.Pointer(&buf[0]))
			end := off + uintptr(us.Length)
			if off >= uintptr(len(buf)) || end > uintptr(len(buf)) {
				return ""
			}
			return utf16Bytes(buf[off:end])
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) && !errors.Is(err, windows.STATUS_BUFFER_TOO_SMALL) && !errors.Is(err, windows.STATUS_BUFFER_OVERFLOW) {
			return ""
		}
		if ret <= size || ret > 1<<20 {
			return ""
		}
		size = ret
	}
	return ""
}

func utf16Bytes(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return windows.UTF16ToString(u)
}

// processBasicInformation is PROCESS_BASIC_INFORMATION with addresses as integers.
type processBasicInformation struct {
	ExitStatus                   int32
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// processCurrentDirectory reads RTL_USER_PROCESS_PARAMETERS.CurrentDirectory from the
// process's PEB. It needs PROCESS_QUERY_INFORMATION and PROCESS_VM_READ, and it is
// best effort: protected processes refuse it and exited ones have no memory left.
func processCurrentDirectory(h windows.Handle) string {
	var pbi processBasicInformation
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil); err != nil || pbi.PebBaseAddress == 0 {
		return ""
	}
	var params uintptr
	if !readRemote(h, pbi.PebBaseAddress+unsafe.Offsetof(windows.PEB{}.ProcessParameters), unsafe.Pointer(&params), unsafe.Sizeof(params)) || params == 0 {
		return ""
	}
	var cd remoteUnicodeString
	if !readRemote(h, params+unsafe.Offsetof(windows.RTL_USER_PROCESS_PARAMETERS{}.CurrentDirectory), unsafe.Pointer(&cd), unsafe.Sizeof(cd)) {
		return ""
	}
	if cd.Length == 0 || cd.Length%2 != 0 || cd.Buffer == 0 {
		return ""
	}
	buf := make([]uint16, cd.Length/2)
	if !readRemote(h, cd.Buffer, unsafe.Pointer(&buf[0]), uintptr(cd.Length)) {
		return ""
	}
	return windows.UTF16ToString(buf)
}

func readRemote(h windows.Handle, addr uintptr, dst unsafe.Pointer, n uintptr) bool {
	var got uintptr
	return windows.ReadProcessMemory(h, addr, (*byte)(dst), n, &got) == nil && got == n
}

func processUserSID(h windows.Handle) string {
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) != nil {
		return ""
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil || u.User.Sid == nil {
		return ""
	}
	return u.User.Sid.String()
}

// wellKnownUser returns the canonical names of the service accounts. Security events
// name LocalSystem after the computer account ("HOST$"), Sysmon calls it
// "NT AUTHORITY\SYSTEM"; the SID decides.
func wellKnownUser(sid string) (name, domain string, ok bool) {
	switch sid {
	case "S-1-5-18":
		return "SYSTEM", "NT AUTHORITY", true
	case "S-1-5-19":
		return "LOCAL SERVICE", "NT AUTHORITY", true
	case "S-1-5-20":
		return "NETWORK SERVICE", "NT AUTHORITY", true
	}
	return "", "", false
}

// userCache resolves SIDs to account names.
type userCache struct {
	mu sync.Mutex
	m  map[string][2]string
}

func newUserCache() *userCache { return &userCache{m: map[string][2]string{}} }

// user returns a User for a SID; the name is empty when the SID cannot be resolved.
func (c *userCache) user(sid string) *event.User {
	if sid == "" {
		return nil
	}
	if n, d, ok := wellKnownUser(sid); ok {
		return &event.User{ID: sid, Name: n, Domain: d}
	}
	c.mu.Lock()
	v, ok := c.m[sid]
	c.mu.Unlock()
	if !ok {
		if s, err := windows.StringToSid(sid); err == nil {
			if acct, dom, _, err := s.LookupAccount(""); err == nil {
				v = [2]string{acct, dom}
			}
		}
		c.mu.Lock()
		if len(c.m) > 4096 {
			clear(c.m)
		}
		c.m[sid] = v
		c.mu.Unlock()
	}
	return &event.User{ID: sid, Name: v[0], Domain: v[1]}
}

// fileKey identifies file content cheaply: if none of these changed, neither did the
// version resource or the hash.
type fileKey struct {
	path  string
	size  int64
	mtime int64
}

func fileKeyOf(path string, fi os.FileInfo) fileKey {
	return fileKey{path: strings.ToLower(path), size: fi.Size(), mtime: fi.ModTime().UnixNano()}
}

// peCache caches version resources by path, size and modification time.
type peCache struct {
	c *lru[fileKey, *event.PE]
}

func newPECache() *peCache { return &peCache{c: newLRU[fileKey, *event.PE](4096)} }

// lookup returns the version resource of an executable, or nil.
func (p *peCache) lookup(path string) *event.PE {
	if path == "" || !filepath.IsAbs(path) {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	k := fileKeyOf(path, fi)
	if v, ok := p.c.get(k); ok {
		return clonePE(v)
	}
	v, _ := readVersionInfo(path)
	p.c.put(k, v)
	return clonePE(v)
}

func clonePE(p *event.PE) *event.PE {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

var (
	modversion                    = windows.NewLazySystemDLL("version.dll")
	procGetFileVersionInfoSizeExW = modversion.NewProc("GetFileVersionInfoSizeExW")
	procGetFileVersionInfoExW     = modversion.NewProc("GetFileVersionInfoExW")
)

// fileVerGetNeutral (FILE_VER_GET_NEUTRAL) reads the version resource of the file
// itself instead of its language (.mui) resource file, whose OriginalFilename would be
// "Cmd.Exe.MUI" rather than "Cmd.Exe".
const fileVerGetNeutral = 0x02

// readVersionInfo reads the string table of a file's version resource, the same
// fields Sysmon reports: OriginalFilename, CompanyName, ProductName, FileDescription and
// FileVersion.
func readVersionInfo(path string) (*event.PE, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var handle uint32
	r, _, e := procGetFileVersionInfoSizeExW.Call(fileVerGetNeutral, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&handle)))
	size := uint32(r)
	if size == 0 {
		return nil, e
	}
	buf := make([]byte, size)
	block := unsafe.Pointer(&buf[0])
	if r, _, e := procGetFileVersionInfoExW.Call(fileVerGetNeutral, uintptr(unsafe.Pointer(p)), 0, uintptr(size), uintptr(block)); r == 0 {
		return nil, e
	}
	var langs []string
	var tp unsafe.Pointer
	var tl uint32
	if windows.VerQueryValue(block, `\VarFileInfo\Translation`, unsafe.Pointer(&tp), &tl) == nil && tp != nil {
		off := uintptr(tp) - uintptr(block)
		for i := uintptr(0); i+4 <= uintptr(tl) && off+i+4 <= uintptr(len(buf)); i += 4 {
			lang := binary.LittleEndian.Uint16(buf[off+i:])
			cp := binary.LittleEndian.Uint16(buf[off+i+2:])
			langs = append(langs, fmt.Sprintf("%04X%04X", lang, cp))
		}
	}
	// Common tables for files whose translation list is missing or wrong.
	langs = append(langs, "040904B0", "040904E4", "04090000", "000004B0")
	str := func(lang, name string) string {
		var p unsafe.Pointer
		var n uint32
		if windows.VerQueryValue(block, `\StringFileInfo\`+lang+`\`+name, unsafe.Pointer(&p), &n) != nil || p == nil || n == 0 {
			return ""
		}
		off := uintptr(p) - uintptr(block)
		end := off + uintptr(n)*2
		if off >= uintptr(len(buf)) {
			return ""
		}
		if end > uintptr(len(buf)) {
			end = uintptr(len(buf))
		}
		return strings.TrimSpace(utf16Bytes(buf[off:end]))
	}
	for _, l := range langs {
		pe := event.PE{
			OriginalFileName: str(l, "OriginalFilename"),
			Company:          str(l, "CompanyName"),
			Product:          str(l, "ProductName"),
			Description:      str(l, "FileDescription"),
			FileVersion:      str(l, "FileVersion"),
		}
		if pe != (event.PE{}) {
			return &pe, nil
		}
	}
	return nil, nil
}
