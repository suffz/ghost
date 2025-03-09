package process_monitor

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/lxn/win"
)

var (
	user32                          = syscall.NewLazyDLL("user32.dll")
	procEnumWindows                 = user32.NewProc("EnumWindows")
	procGetWindowTextW              = user32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW        = user32.NewProc("GetWindowTextLengthW")
	modShell32                      = syscall.NewLazyDLL("shell32.dll")
	procSHGetPropertyStoreForWindow = modShell32.NewProc("SHGetPropertyStoreForWindow")
)

func EnumWindows(enumFunc uintptr, lParam uintptr) bool {
	ret, _, _ := procEnumWindows.Call(enumFunc, lParam)
	return ret != 0
}

func getWindowText(hwnd win.HWND) string {
	length, _, _ := procGetWindowTextLengthW.Call(uintptr(hwnd))
	if length == 0 {
		return ""
	}
	buf := make([]uint16, length+1)
	procGetWindowTextW.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&buf[0])),
		length+1,
	)
	return syscall.UTF16ToString(buf)
}

type PROPERTYKEY struct {
	Fmtid syscall.GUID
	PID   uint32
}

var PKEY_AppUserModel_ID = PROPERTYKEY{
	Fmtid: syscall.GUID{
		Data1: 0x9F4C2855,
		Data2: 0x9F79,
		Data3: 0x4B39,
		Data4: [8]byte{0xA8, 0xD0, 0xE1, 0xD4, 0x2D, 0x1D, 0x5F, 0x03},
	},
	PID: 5,
}

type PROPVARIANT struct {
	vt         uint16
	wReserved1 uint16
	wReserved2 uint16
	wReserved3 uint16
	pwszVal    uintptr
}

var (
	modOle32             = syscall.NewLazyDLL("ole32.dll")
	procPropVariantClear = modOle32.NewProc("PropVariantClear")
)

var IID_IPropertyStore = ole.NewGUID("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")

func PropVariantClear(pv *PROPVARIANT) error {
	hr, _, _ := procPropVariantClear.Call(uintptr(unsafe.Pointer(pv)))
	if hr != 0 {
		return fmt.Errorf("PropVariantClear failed: 0x%x", hr)
	}
	return nil
}

type enumData struct {
	targetPID uint32
	found     bool
	uwp       bool
}

var enumProcCallback = syscall.NewCallback(enumProc)

func enumProc(hwnd uintptr, lParam uintptr) uintptr {
	data := (*enumData)(unsafe.Pointer(lParam))
	h := win.HWND(hwnd)
	if !win.IsWindowVisible(h) {
		return 1
	}
	title := getWindowText(h)
	if data.uwp {
		classBuf := make([]uint16, 256)
		win.GetClassName(h, &classBuf[0], int(len(classBuf)))
		if syscall.UTF16ToString(classBuf) == "ApplicationFrameWindow" {
			data.found = true
			return 0
		}
	}
	var pid uint32
	win.GetWindowThreadProcessId(h, &pid)
	if pid != data.targetPID || title == "" {
		return 1
	}
	data.found = true
	return 0
}

func IsProcessWindowInTaskbar(targetPID uint32, uwp bool) (bool, error) {
	data := enumData{
		targetPID: targetPID,
		found:     false,
		uwp:       uwp,
	}
	EnumWindows(enumProcCallback, uintptr(unsafe.Pointer(&data)))
	return data.found, nil
}
