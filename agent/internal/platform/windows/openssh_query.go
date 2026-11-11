//go:build windows

package windows

import (
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// queryOpenSSHLogin reads the newest "Accepted ..." record (event 4) that sshd process
// pid logged in OpenSSH/Operational, and returns its key ("" for a password login).
func queryOpenSSHLogin(pid int64) (string, bool) {
	ch, err := windows.UTF16PtrFromString("OpenSSH/Operational")
	if err != nil {
		return "", false
	}
	q, err := windows.UTF16PtrFromString("*[System[EventID=4 and Execution[@ProcessID=" + strconv.FormatInt(pid, 10) + "]]]")
	if err != nil {
		return "", false
	}
	r, _, _ := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath|evtQueryReverseDirection)
	if r == 0 {
		return "", false
	}
	res := evtHandle(r)
	defer evtClose(res)
	var buf []uint16
	for range 4 {
		var ev evtHandle
		var n uint32
		r, _, _ := procEvtNext.Call(uintptr(res), 1, uintptr(unsafe.Pointer(&ev)), uintptr(time.Second/time.Millisecond), 0, uintptr(unsafe.Pointer(&n)))
		if r == 0 || n == 0 {
			return "", false
		}
		text, err := evtRenderString(ev, evtRenderEventXML, &buf)
		evtClose(ev)
		if err != nil {
			continue
		}
		rec, err := parseEventXML(text)
		if err != nil {
			continue
		}
		payload := rec.Data["payload"]
		if !reSSHAccepted.MatchString(payload) {
			continue
		}
		if k := reSSHKey.FindStringSubmatch(payload); k != nil {
			return k[2], true
		}
		return "", true
	}
	return "", false
}
