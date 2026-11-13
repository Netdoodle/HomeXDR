//go:build windows

package windows

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Minimal Windows Filtering Platform (WFP) bindings for host isolation: open the engine,
// add a persistent provider, sublayer and filters in one transaction, and delete them.
// Struct layouts follow fwpmtypes.h / fwptypes.h (64-bit and 32-bit alignment both come
// out right because Go aligns these field types like C does).

var (
	modfwpuclnt                = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0        = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0       = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0  = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0 = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0  = modfwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderAdd0       = modfwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmProviderDelete0    = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmSubLayerAdd0       = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDelete0    = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmSubLayerGetByKey0  = modfwpuclnt.NewProc("FwpmSubLayerGetByKey0")
	procFwpmFilterAdd0         = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByKey0 = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmFreeMemory0        = modfwpuclnt.NewProc("FwpmFreeMemory0")
)

const (
	rpcCAuthnWinNT = 10

	fwpEmpty        = 0
	fwpUint8        = 1
	fwpUint16       = 2
	fwpUint32       = 3
	fwpByteArray16  = 11
	fwpV4AddrMask   = 0x100
	fwpV6AddrMask   = 0x101
	fwpMatchEqual   = 0
	fwpMatchFlagAny = 7

	fwpActionBlock  = 0x1 | 0x1000
	fwpActionPermit = 0x2 | 0x1000

	fwpmProviderFlagPersistent = 0x1
	fwpmSubLayerFlagPersistent = 0x1
	fwpmFilterFlagPersistent   = 0x1
	fwpmFilterFlagClearAction  = 0x8 // a "hard" permit: lower-weight sublayers cannot block it

	fwpConditionFlagIsLoopback = 0x1

	errFwpFilterNotFound   = 0x80320003
	errFwpProviderNotFound = 0x80320005
	errFwpSubLayerNotFound = 0x80320007
)

var (
	layerConnectV4 = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerConnectV6 = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	layerAcceptV4  = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	layerAcceptV6  = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}

	condRemoteAddr = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	condRemotePort = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	condLocalPort  = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	condProtocol   = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	condFlags      = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}

	// HomeXDR's own WFP objects. Filters get keys derived from isoFilterBase plus their
	// index, so release can delete them without enumerating.
	isoProviderKey = windows.GUID{Data1: 0x6b1e0c4d, Data2: 0x5a2f, Data3: 0x4e8b, Data4: [8]byte{0x9d, 0x31, 0x48, 0x58, 0x44, 0x52, 0x00, 0x01}}
	isoSubLayerKey = windows.GUID{Data1: 0x6b1e0c4d, Data2: 0x5a2f, Data3: 0x4e8b, Data4: [8]byte{0x9d, 0x31, 0x48, 0x58, 0x44, 0x52, 0x00, 0x02}}
	isoFilterBase  = windows.GUID{Data1: 0x6b1e0c4e, Data2: 0x5a2f, Data3: 0x4e8b, Data4: [8]byte{0x9d, 0x31, 0x48, 0x58, 0x44, 0x52, 0x00, 0x00}}
)

func isoFilterKey(i int) windows.GUID {
	k := isoFilterBase
	k.Data4[6], k.Data4[7] = byte(i>>8), byte(i)
	return k
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpByteBlob struct {
	size uint32
	data *uint8
}

type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

type fwpmSubLayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

// fwpValue0 and fwpConditionValue0 share a layout: a type and an 8-byte union.
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpmFilterCondition0 struct {
	fieldKey  windows.GUID
	matchType uint32
	value     fwpValue0
}

type fwpmAction0 struct {
	typ uint32
	key windows.GUID
}

type fwpmFilter0 struct {
	filterKey       windows.GUID
	displayData     fwpmDisplayData0
	flags           uint32
	providerKey     *windows.GUID
	providerData    fwpByteBlob
	layerKey        windows.GUID
	subLayerKey     windows.GUID
	weight          fwpValue0
	numConditions   uint32
	conditions      *fwpmFilterCondition0
	action          fwpmAction0
	providerContext [2]uint64 // union { UINT64 rawContext; GUID providerContextKey }
	reserved        *windows.GUID
	filterID        uint64
	effectiveWeight fwpValue0
}

type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

type fwpV6AddrAndMask struct {
	addr      [16]byte
	prefixLen uint8
}

func fwpErr(op string, r uintptr) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", op, windows.Errno(r))
}

func isFwp(err error, code uint32) bool {
	var e windows.Errno
	return errors.As(err, &e) && uint32(e) == code
}

type wfpEngine struct{ h windows.Handle }

func openWFP() (*wfpEngine, error) {
	if err := modfwpuclnt.Load(); err != nil {
		return nil, fmt.Errorf("Windows Filtering Platform not available: %w", err)
	}
	var h windows.Handle
	r, _, _ := procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&h)))
	if err := fwpErr("FwpmEngineOpen0", r); err != nil {
		return nil, err
	}
	return &wfpEngine{h: h}, nil
}

func (e *wfpEngine) close() { procFwpmEngineClose0.Call(uintptr(e.h)) }

// tx runs fn in a WFP transaction, committing on success and aborting on error.
func (e *wfpEngine) tx(fn func() error) error {
	r, _, _ := procFwpmTransactionBegin0.Call(uintptr(e.h), 0)
	if err := fwpErr("FwpmTransactionBegin0", r); err != nil {
		return err
	}
	if err := fn(); err != nil {
		procFwpmTransactionAbort0.Call(uintptr(e.h))
		return err
	}
	r, _, _ = procFwpmTransactionCommit0.Call(uintptr(e.h))
	return fwpErr("FwpmTransactionCommit0", r)
}

func display(name, desc string) fwpmDisplayData0 {
	n, _ := windows.UTF16PtrFromString(name)
	d, _ := windows.UTF16PtrFromString(desc)
	return fwpmDisplayData0{name: n, description: d}
}

func (e *wfpEngine) addProviderAndSubLayer() error {
	p := fwpmProvider0{
		providerKey: isoProviderKey,
		displayData: display("HomeXDR", "HomeXDR agent network isolation"),
		flags:       fwpmProviderFlagPersistent,
	}
	r, _, _ := procFwpmProviderAdd0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&p)), 0)
	runtime.KeepAlive(&p)
	if err := fwpErr("FwpmProviderAdd0", r); err != nil {
		return err
	}
	pk := isoProviderKey
	s := fwpmSubLayer0{
		subLayerKey: isoSubLayerKey,
		displayData: display("HomeXDR isolation", "Blocks all traffic except the HomeXDR server while the host is isolated"),
		flags:       fwpmSubLayerFlagPersistent,
		providerKey: &pk,
		weight:      0xffff,
	}
	r, _, _ = procFwpmSubLayerAdd0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&s)), 0)
	runtime.KeepAlive(&s)
	return fwpErr("FwpmSubLayerAdd0", r)
}

// deleteAll removes HomeXDR's filters, sublayer and provider. Missing objects are fine.
func (e *wfpEngine) deleteAll() error {
	for i := 0; i < wfpMaxFilters; i++ {
		k := isoFilterKey(i)
		r, _, _ := procFwpmFilterDeleteByKey0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&k)))
		if err := fwpErr("FwpmFilterDeleteByKey0", r); err != nil {
			if isFwp(err, errFwpFilterNotFound) {
				break // keys are contiguous from 0
			}
			return err
		}
	}
	k := isoSubLayerKey
	r, _, _ := procFwpmSubLayerDelete0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&k)))
	if err := fwpErr("FwpmSubLayerDeleteByKey0", r); err != nil && !isFwp(err, errFwpSubLayerNotFound) {
		return err
	}
	k = isoProviderKey
	r, _, _ = procFwpmProviderDelete0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&k)))
	if err := fwpErr("FwpmProviderDeleteByKey0", r); err != nil && !isFwp(err, errFwpProviderNotFound) {
		return err
	}
	return nil
}

func (e *wfpEngine) subLayerExists() bool {
	k := isoSubLayerKey
	var out uintptr
	r, _, _ := procFwpmSubLayerGetByKey0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&out)))
	if r != 0 {
		return false
	}
	procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&out)))
	return true
}

// addFilter adds one rule as filter number i.
func (e *wfpEngine) addFilter(i int, f wfpRule) error {
	var keep []any // pointed-to values the union fields refer to
	var conds []fwpmFilterCondition0
	if f.loopback {
		conds = append(conds, fwpmFilterCondition0{fieldKey: condFlags, matchType: fwpMatchFlagAny,
			value: fwpValue0{typ: fwpUint32, value: fwpConditionFlagIsLoopback}})
	}
	if f.remote.IsValid() {
		p := f.remote.Masked()
		if a := p.Addr(); a.Is4() {
			b := a.As4()
			addr := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
			if p.Bits() == 32 {
				conds = append(conds, fwpmFilterCondition0{fieldKey: condRemoteAddr, matchType: fwpMatchEqual,
					value: fwpValue0{typ: fwpUint32, value: uintptr(addr)}})
			} else {
				m := &fwpV4AddrAndMask{addr: addr, mask: ^uint32(0) << (32 - p.Bits())}
				if p.Bits() == 0 {
					m.mask = 0
				}
				keep = append(keep, m)
				conds = append(conds, fwpmFilterCondition0{fieldKey: condRemoteAddr, matchType: fwpMatchEqual,
					value: fwpValue0{typ: fwpV4AddrMask, value: uintptr(unsafe.Pointer(m))}})
			}
		} else {
			if p.Bits() == 128 {
				b := new([16]byte)
				*b = a.As16()
				keep = append(keep, b)
				conds = append(conds, fwpmFilterCondition0{fieldKey: condRemoteAddr, matchType: fwpMatchEqual,
					value: fwpValue0{typ: fwpByteArray16, value: uintptr(unsafe.Pointer(b))}})
			} else {
				m := &fwpV6AddrAndMask{addr: a.As16(), prefixLen: uint8(p.Bits())}
				keep = append(keep, m)
				conds = append(conds, fwpmFilterCondition0{fieldKey: condRemoteAddr, matchType: fwpMatchEqual,
					value: fwpValue0{typ: fwpV6AddrMask, value: uintptr(unsafe.Pointer(m))}})
			}
		}
	}
	if f.proto != 0 {
		conds = append(conds, fwpmFilterCondition0{fieldKey: condProtocol, matchType: fwpMatchEqual,
			value: fwpValue0{typ: fwpUint8, value: uintptr(f.proto)}})
	}
	if f.remotePort != 0 {
		conds = append(conds, fwpmFilterCondition0{fieldKey: condRemotePort, matchType: fwpMatchEqual,
			value: fwpValue0{typ: fwpUint16, value: uintptr(f.remotePort)}})
	}
	if f.localPort != 0 {
		conds = append(conds, fwpmFilterCondition0{fieldKey: condLocalPort, matchType: fwpMatchEqual,
			value: fwpValue0{typ: fwpUint16, value: uintptr(f.localPort)}})
	}
	pk := isoProviderKey
	flt := fwpmFilter0{
		filterKey:   isoFilterKey(i),
		displayData: display("HomeXDR isolation: "+f.name, "Added by the HomeXDR agent while the host is isolated"),
		flags:       fwpmFilterFlagPersistent,
		providerKey: &pk,
		layerKey:    f.layer,
		subLayerKey: isoSubLayerKey,
		weight:      fwpValue0{typ: fwpUint8, value: 0},
		action:      fwpmAction0{typ: fwpActionBlock},
	}
	if f.permit {
		flt.action.typ = fwpActionPermit
		flt.flags |= fwpmFilterFlagClearAction
		flt.weight.value = 15
	}
	if len(conds) > 0 {
		flt.numConditions = uint32(len(conds))
		flt.conditions = &conds[0]
	} else {
		flt.weight = fwpValue0{typ: fwpUint8, value: 0}
	}
	var id uint64
	r, _, _ := procFwpmFilterAdd0.Call(uintptr(e.h), uintptr(unsafe.Pointer(&flt)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(&flt)
	runtime.KeepAlive(conds)
	runtime.KeepAlive(keep)
	return fwpErr(fmt.Sprintf("FwpmFilterAdd0 (%s)", f.name), r)
}
