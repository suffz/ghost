package memory

/*
#include <windows.h>
#include <dbghelp.h>
#include <stdlib.h>

#cgo LDFLAGS: -ldbghelp

char* demangle(char* mangled) {
    char demangled[1024] = {0};
    DWORD len = UnDecorateSymbolName(mangled, demangled, sizeof(demangled), UNDNAME_COMPLETE);
    if(len == 0) return mangled;
    return strdup(demangled);
}
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	ntdll                     = syscall.NewLazyDLL("ntdll.dll")
	modpsapi                  = windows.NewLazySystemDLL("psapi.dll")
	user32                    = syscall.NewLazyDLL("user32.dll")
	procOpenProcess           = kernel32.NewProc("OpenProcess")
	procVirtualQueryEx        = kernel32.NewProc("VirtualQueryEx")
	procVirtualAllocEx        = kernel32.NewProc("VirtualAllocEx")
	procNtUnlockVirtualMemory = ntdll.NewProc("NtUnlockVirtualMemory")
	procSendMessage           = user32.NewProc("SendMessageA")
	ntReadVirtualMemory       = ntdll.NewProc("NtReadVirtualMemory")
	procWriteProcessMemory    = kernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory     = kernel32.NewProc("ReadProcessMemory")
	procQueryWorkingSetEx     = modpsapi.NewProc("QueryWorkingSetEx")
)

type RTTICompleteObjectLocator struct {
	Signature       uint32
	Offset          uint32
	CdOffset        uint32
	TypeDescriptor  uint32
	ClassDescriptor uint32
	BaseOffset      uint32
}

type TypeDescriptor struct {
	Vtable uintptr
	Ptr    uint64
	Name   [255]byte
}

type Processes struct {
	Name string
	Pid  uint32
}

type ModuleInfo struct {
	BaseAddress uintptr
	Size        uint32
}

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF

	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40

	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_RELEASE = 0x8000

	MEM_DECOMMIT = 0x4000
)

var ALLOWED_PROTECTIONS = []uint32{
	PAGE_READONLY,
	PAGE_READWRITE,
	PAGE_EXECUTE_READ,
	PAGE_EXECUTE_READWRITE,
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

var pg = syscall.Getpagesize()

type Luna struct {
	ProcessHandle     syscall.Handle
	Is64Bit           bool
	RobloxBase        uintptr
	AllocAddr         uintptr
	InstanceContainer []uintptr
	Pid               uint32
	modules           []ModuleInfo
}

func SendMessage(hwnd win.HWND, msg uint32, wParam, lParam uintptr) error {
	ret, _, err := procSendMessage.Call(
		uintptr(hwnd),
		uintptr(msg),
		wParam,
		lParam,
	)
	if ret == 0 {
		return err
	}
	return nil
}

func IsHandleValid(h syscall.Handle) bool {
	var exitCode uint32
	err := syscall.GetExitCodeProcess(h, &exitCode)
	if err != nil || exitCode != 259 {
		return false
	}
	return true
}

func NewLuna(pid uint32) (*Luna, error) {
	handle, _, err := procOpenProcess.Call(
		0x1F0FFF,
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return nil, err
	}

	new := &Luna{
		ProcessHandle: syscall.Handle(handle),
		Is64Bit:       true,
		Pid:           pid,
	}

	base, err := new.GetBaseAddr(pid, "RobloxPlayerBeta", "Windows10Universal", "eurotrucks2")
	if err != nil {
		return nil, nil
	}
	new.RobloxBase = base

	return new, nil
}

func (m *Luna) IsWorkingSet(address uintptr) bool {
	var wsInfo = struct {
		VirtualAddress    uintptr
		VirtualAttributes uintptr
	}{VirtualAddress: address & ^(uintptr(pg) - 1), VirtualAttributes: 0}
	procQueryWorkingSetEx.Call(
		uintptr(m.ProcessHandle),
		uintptr(unsafe.Pointer(&wsInfo)),
		uintptr(unsafe.Sizeof(wsInfo)),
	)
	return (wsInfo.VirtualAttributes & 0x1) != 0
}

func (m *Luna) WaitUntilPossiblyReadable(address uintptr) {
	var i = 0
	for !m.IsWorkingSet(address) {
		i++
		if i > 300 {
			break
		}
	}
}

func (m *Luna) MemRead(address uintptr, buffer unsafe.Pointer, size uintptr) error {

	if m == nil || !IsHandleValid(m.ProcessHandle) {
		return errors.New("Invalid memory address")
	}

	if m.AllocAddr > 0 {
		procReadProcessMemory.Call(
			uintptr(m.ProcessHandle),
			address,
			uintptr(buffer),
			size,
			0,
		)
		return nil
	}

	m.WaitUntilPossiblyReadable(address)

	var mbi MEMORY_BASIC_INFORMATION
	mbiSize := uintptr(unsafe.Sizeof(mbi))

	procVirtualQueryEx.Call(
		uintptr(m.ProcessHandle),
		address,
		uintptr(unsafe.Pointer(&mbi)),
		mbiSize,
	)

	ntReadVirtualMemory.Call(
		uintptr(m.ProcessHandle),
		address,
		uintptr(buffer),
		size,
		0,
	)

	baddr := mbi.AllocationBase
	s := mbi.RegionSize

	procNtUnlockVirtualMemory.Call(
		uintptr(m.ProcessHandle),
		uintptr(unsafe.Pointer(&baddr)),
		uintptr(unsafe.Pointer(&s)),
		1,
	)

	return nil
}

func (m *Luna) MemWrite(address uintptr, buffer unsafe.Pointer, size uintptr) error {

	if m == nil || !IsHandleValid(m.ProcessHandle) {
		return errors.New("Invalid memory address")
	}

	var bytesWritten uintptr
	status, _, err := procWriteProcessMemory.Call(
		uintptr(m.ProcessHandle),
		address,
		uintptr(buffer),
		size,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if status == 0 {
		return fmt.Errorf("WriteProcessMemory failed at address %#x: %v", address, err)
	}
	/*
		m.WaitUntilPossiblyReadable(address)

		var mbi MemoryBasicInformation
		mbiSize := uintptr(unsafe.Sizeof(mbi))

		procVirtualQueryEx.Call(
			uintptr(m.ProcessHandle),
			address,
			uintptr(unsafe.Pointer(&mbi)),
			mbiSize,
		)

		var bytesWritten uintptr
		status, _, err := procWriteProcessMemory.Call(
			uintptr(m.ProcessHandle),
			address,
			uintptr(buffer),
			size,
			uintptr(unsafe.Pointer(&bytesWritten)),
		)

		baddr := mbi.AllocationBase
		s := mbi.RegionSize

		m.UnlockMemory(baddr, s)

		if status == 0 {
			return fmt.Errorf("WriteProcessMemory failed at address %#x: %v", address, err)
		}

		if bytesWritten < size {
			return fmt.Errorf("only wrote %d bytes out of %d requested to address %#x", bytesWritten, size, address)
		}
	*/
	return nil
}

func (m *Luna) PointerSize() uintptr {

	if m == nil {
		return 8
	}

	if m.Is64Bit {
		return 8
	}
	return 4
}

func (m *Luna) AllocateMemory(size uintptr) (uintptr, error) {
	if m == nil || !IsHandleValid(m.ProcessHandle) {
		return 0, errors.New("Invalid memory address")
	}
	addr, _, err := procVirtualAllocEx.Call(
		uintptr(m.ProcessHandle),
		0,
		size,
		windows.MEM_COMMIT,
		windows.PAGE_READWRITE,
	)
	if addr == 0 {
		return 0, err
	}
	return addr, nil
}

func (m *Luna) ReadMemory(address uintptr, size uintptr) ([]byte, error) {

	if m == nil || !IsHandleValid(m.ProcessHandle) {
		return []byte{}, errors.New("Invalid memory address")
	}

	buffer := make([]byte, size)
	err := m.MemRead(address, unsafe.Pointer(&buffer[0]), size)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

func (m *Luna) WriteMemory(address uintptr, data []byte, size uintptr) error {
	if len(data) == 0 {
		return errors.New("Byte size is empty!")
	}
	return m.MemWrite(address, unsafe.Pointer(&data[0]), size)
}

func (m *Luna) ReadByte(address uintptr) (byte, error) {

	var result byte
	err := m.MemRead(address, unsafe.Pointer(&result), 1)
	if err != nil {
		return 0, err
	}
	return result, nil
}

func (m *Luna) ReadBytes(address uintptr, length uintptr) ([]byte, error) {
	return m.ReadMemory(address, length)
}

func (m *Luna) ReadString(address uintptr, maxLength uintptr) (string, error) {
	if maxLength > 1000 || maxLength == 0 {
		maxLength = 100
	}
	buffer := make([]byte, maxLength)
	err := m.MemRead(address, unsafe.Pointer(&buffer[0]), maxLength)
	if err != nil {
		return "", err
	}
	idx := bytes.IndexByte(buffer, 0)
	if idx != -1 {
		buffer = buffer[:idx]
	}
	return string(buffer), nil
}

func (m *Luna) ReadDouble(address uintptr) (float64, error) {
	var result float64
	err := m.MemRead(address, unsafe.Pointer(&result), m.PointerSize())
	if err != nil {
		return 0, err
	}
	return result, nil
}

func (m *Luna) ReadFloat(address uintptr) (float32, error) {
	var result float32
	err := m.MemRead(address, unsafe.Pointer(&result), m.PointerSize())
	if err != nil {
		return 0, err
	}
	return result, nil
}

func (m *Luna) ReadInt32(address uintptr) (int32, error) {
	var result int32
	err := m.MemRead(address, unsafe.Pointer(&result), m.PointerSize())
	if err != nil {
		return 0, err
	}
	return result, nil
}

func (m *Luna) ReadInt64(address uintptr) (int64, error) {
	var result int64
	err := m.MemRead(address, unsafe.Pointer(&result), m.PointerSize())
	if err != nil {
		return 0, err
	}
	return result, nil
}

func (mem *Luna) ReadRbxStr(address uintptr) (string, error) {
	var strCheck uint64
	err := mem.MemRead(address+0x10, unsafe.Pointer(&strCheck), unsafe.Sizeof(strCheck))
	if err != nil {
		return "", err
	}

	if strCheck > 15 {
		var strPointer uint64
		err = mem.MemRead(address, unsafe.Pointer(&strPointer), unsafe.Sizeof(strPointer))
		if err != nil {
			return "", err
		}
		return mem.ReadString(uintptr(strPointer), uintptr(strCheck))
	}

	return mem.ReadString(address, uintptr(strCheck))
}

func (m *Luna) MustPointer(p uintptr, _ error) uintptr {
	return p
}

func (m *Luna) ReadPointer(address uintptr) (uintptr, error) {
	if m.Is64Bit {
		val, err := m.ReadUint64(address)
		return uintptr(val), err
	} else {
		val, err := m.ReadUint32(address)
		return uintptr(val), err
	}
}

func (m *Luna) ReadUint32(address uintptr) (uint32, error) {
	var result uint32
	err := m.MemRead(address, unsafe.Pointer(&result), unsafe.Sizeof(result))
	if err != nil {
		return 0, err
	}
	return result, nil
}

func (m *Luna) ReadUint64(address uintptr) (uint64, error) {
	var result uint64
	err := m.MemRead(address, unsafe.Pointer(&result), unsafe.Sizeof(result))
	if err != nil {
		return 0, err
	}
	return result, nil
}

func (m *Luna) WriteByte(address uintptr, value byte) error {
	return m.MemWrite(address, unsafe.Pointer(&value), 1)
}

func (m *Luna) WriteBytes(address uintptr, data []byte, size uintptr) error {
	return m.WriteMemory(address, data, size)
}

func (m *Luna) WriteString(address uintptr, value string) error {
	data := append([]byte(value), 0)
	return m.WriteBytes(address, data, uintptr(len(data)))
}

func (m *Luna) WriteDouble(address uintptr, value float64) error {
	return m.MemWrite(address, unsafe.Pointer(&value), m.PointerSize())
}

func (m *Luna) WriteFloat(address uintptr, value float32) error {
	return m.MemWrite(address, unsafe.Pointer(&value), m.PointerSize())
}

func (m *Luna) WriteInt32(address uintptr, value int32) error {
	return m.MemWrite(address, unsafe.Pointer(&value), m.PointerSize())
}

func (m *Luna) WriteInt64(address uintptr, value int64) error {
	return m.MemWrite(address, unsafe.Pointer(&value), m.PointerSize())
}

func (m *Luna) WritePointer(address uintptr, value uintptr) error {
	if m.Is64Bit {
		val := uint64(value)
		return m.MemWrite(address, unsafe.Pointer(&val), m.PointerSize())
	} else {
		val := uint32(value)
		return m.MemWrite(address, unsafe.Pointer(&val), m.PointerSize())
	}
}

func GetProcesses() ([]Processes, error) {
	var processNames []Processes
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.Contains(name, "RobloxPlayerBeta") ||
			strings.Contains(name, "Windows10Universal") ||
			strings.Contains(name, "eurotrucks2") {
			processNames = append(processNames, Processes{
				Name: name,
				Pid:  entry.ProcessID,
			})
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, err
		}
		time.Sleep(time.Millisecond * 15)
	}

	return processNames, nil
}

func removeEuro(data []Processes) []Processes {
	var RemovedRobloxs []Processes
	for _, inst := range data {
		if inst.Name != "RobloxPlayerBeta.exe" && inst.Name != "Windows10Universal.exe" {
			inst.Name = "RobloxPlayerBeta.exe"
			RemovedRobloxs = append(RemovedRobloxs, inst)
		} else {
			RemovedRobloxs = append(RemovedRobloxs, inst)
		}
	}
	return RemovedRobloxs
}

func IsProcessRunning() (bool, []Processes) {
	processes, err := GetProcesses()
	if err != nil {
		log.Fatal(err)
	}
	processes = removeEuro(processes)
	return len(processes) != 0, processes
}

func GetLatestLogFile(dir string) (string, error) {
	var latestFile string
	var latestTime time.Time

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".log" {
			if info.ModTime().After(latestTime) {
				latestFile = path
				latestTime = info.ModTime()
			}
		}
		return nil
	})

	if err != nil {
		return "", err
	}
	if latestFile == "" {
		return "", errors.New("no log files found")
	}
	return latestFile, nil
}

func LocateTID(logFile string) (uintptr, error) {
	content, err := ioutil.ReadFile(logFile)
	if err != nil {
		return 0, err
	}
	var tid uint64
	fmt.Sscanf(strings.Replace(strings.Split(strings.Split(strings.Split(string(content), "::replaceDataModel:")[1], "[tid:")[1], "]")[0], "0x", "", 1), "%x", &tid)
	return uintptr(tid), nil
}

func demangleSymbol(mangled string) string {

	adjusted := mangled
	if strings.HasPrefix(adjusted, ".?AV") {
		adjusted = "?" + adjusted[4:]
	} else if strings.HasPrefix(adjusted, ".?A") {
		adjusted = "?" + adjusted[3:]
	}

	cstr := C.CString(adjusted)
	defer C.free(unsafe.Pointer(cstr))

	var demangled [1024]C.char
	if C.UnDecorateSymbolName(
		cstr,
		&demangled[0],
		C.ulong(len(demangled)),
		C.UNDNAME_COMPLETE,
	) == 0 {
		return mangled
	}

	result := C.GoString(&demangled[0])
	result = strings.ReplaceAll(result, "?", "")
	result = strings.TrimSpace(result)

	return result
}
func RTTIInformation(process *Luna, address uintptr) (string, error) {
	vtable, err := process.ReadPointer(address)
	if err != nil {
		return "", err
	}

	colPtr, err := process.ReadPointer(vtable - 8)
	if err != nil {
		return "", err
	}

	col := RTTICompleteObjectLocator{}
	if err := process.MemRead(colPtr, unsafe.Pointer(&col), uintptr(unsafe.Sizeof(col))); err != nil {
		return "", err
	}

	moduleBase, err := process.GetModuleBase(colPtr)
	if err != nil {
		return "", err
	}

	typeDescAddr := moduleBase + uintptr(col.TypeDescriptor)
	td := TypeDescriptor{}
	if err := process.MemRead(typeDescAddr, unsafe.Pointer(&td), uintptr(unsafe.Sizeof(td))); err != nil {
		return "", err
	}

	mangled, err := extractMangledName(td.Name)
	if err != nil {
		return "", fmt.Errorf("invalid type name: %w", err)
	}

	demangled := demangleSymbol(mangled)
	if err := validateDemangledName(demangled); err != nil {
		return "", fmt.Errorf("invalid demangled name: %w", err)
	}

	return demangled, nil
}

func FindDataModel(process *Luna, tid uintptr, locate ...string) (uintptr, error) {
	var dataModel uintptr
	cache := make(map[uintptr]struct{})

	var walk func(uintptr, uintptr, int) bool
	walk = func(address, maxOffset uintptr, depth int) bool {
		for offset := uintptr(0); offset < maxOffset; offset += 8 {
			current := address + offset
			if _, exists := cache[current]; exists {
				continue
			}

			ptr, err := process.ReadPointer(current)
			if err != nil || ptr == 0 {
				continue
			}

			if name, err := RTTIInformation(process, ptr); err == nil {
				//fmt.Printf("%v: %x\n", name, ptr)
				for _, compare := range locate {
					if strings.Contains(name, compare) {
						dataModel = ptr
						return false
					}
				}
			}

			if depth < 5 {
				if !walk(ptr, 0x200, depth+1) {
					return false
				}
			}

			cache[current] = struct{}{}
		}
		return true
	}

	walk(tid, 22160, 0)

	return dataModel, nil
}

func (p *Luna) GetModuleBase(address uintptr) (uintptr, error) {
	if p.modules == nil {
		if err := p.EnumModules(); err != nil {
			return 0, err
		}
	}

	for _, module := range p.modules {
		if address >= module.BaseAddress && address < module.BaseAddress+uintptr(module.Size) {
			return module.BaseAddress, nil
		}
	}
	return 0, errors.New("module not found")
}

func (p *Luna) EnumModules() error {
	var hMods [1024]windows.Handle
	var cbNeeded uint32

	ret := windows.EnumProcessModules(
		windows.Handle(p.ProcessHandle),
		&hMods[0],
		uint32(len(hMods))*uint32(unsafe.Sizeof(hMods[0])),
		&cbNeeded,
	)
	if ret != nil {
		return windows.GetLastError()
	}

	moduleCount := cbNeeded / uint32(unsafe.Sizeof(hMods[0]))
	p.modules = make([]ModuleInfo, 0, moduleCount)

	for i := 0; i < int(moduleCount); i++ {
		var modInfo windows.ModuleInfo
		err := windows.GetModuleInformation(
			windows.Handle(p.ProcessHandle),
			hMods[i],
			&modInfo,
			uint32(unsafe.Sizeof(modInfo)))

		if err != nil {
			continue
		}

		p.modules = append(p.modules, ModuleInfo{
			BaseAddress: modInfo.BaseOfDll,
			Size:        modInfo.SizeOfImage,
		})
	}
	return nil
}

func extractMangledName(nameBytes [255]byte) (string, error) {
	end := bytes.IndexByte(nameBytes[:], 0)
	if end == -1 {
		return "", fmt.Errorf("name not null-terminated")
	}
	const minLength = 4
	if end < minLength {
		return "", fmt.Errorf("name too short (%d bytes)", end)
	}
	mangled := string(nameBytes[:end])
	for i, c := range mangled {
		if c < 32 || c > 126 {
			return "", fmt.Errorf("invalid character at position %d: 0x%02x", i, byte(c))
		}
	}
	if !strings.HasPrefix(mangled, ".?A") {
		return "", fmt.Errorf("invalid RTTI prefix")
	}

	return mangled, nil
}

func validateDemangledName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("empty name")
	}
	if strings.Contains(name, "??") ||
		strings.Contains(name, "?A") ||
		strings.Contains(name, " ") {
		return fmt.Errorf("suspicious demangling artifacts")
	}
	for i, c := range name {
		if c < 32 || c > 126 {
			return fmt.Errorf("invalid character at position %d: 0x%02x", i, byte(c))
		}
	}
	if !strings.Contains(name, "::") {
		return fmt.Errorf("missing namespace separator")
	}
	return nil
}
