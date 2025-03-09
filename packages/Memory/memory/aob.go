package memory

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (p *Luna) PLAT(aob string) []byte {
	trueB := []byte{}
	aob = strings.ReplaceAll(aob, " ", "")
	PLATlist := []string{}
	for i := 0; i < len(aob); i += 2 {
		PLATlist = append(PLATlist, aob[i:i+2])
	}
	for _, i := range PLATlist {
		if strings.Contains(i, "?") {
			trueB = append(trueB, 0x00)
		} else {
			bytes, _ := hex.DecodeString(i)
			trueB = append(trueB, bytes...)
		}
	}
	return trueB
}

func findAllPatterns(data, pattern []byte, baseAddress uintptr) []uintptr {
	var results []uintptr
	patternLength := len(pattern)
	dataLength := len(data)

	for i := 0; i <= dataLength-patternLength; i++ {
		found := true
		for j := 0; j < patternLength; j++ {
			if pattern[j] != 0x00 && pattern[j] != data[i+j] {
				found = false
				break
			}
		}
		if found {
			results = append(results, baseAddress+uintptr(i))
		}
	}

	return results
}

func findPattern(data, pattern []byte, baseAddress uintptr) uintptr {
	patternLength := len(pattern)
	dataLength := len(data)

	for i := 0; i <= dataLength-patternLength; i++ {
		found := true
		for j := 0; j < patternLength; j++ {
			if pattern[j] != 0x00 && pattern[j] != data[i+j] {
				found = false
				break
			}
		}
		if found {
			return baseAddress + uintptr(i)
		}
	}

	return 0
}

type MemoryReg struct {
	base  uintptr
	size  uintptr
	state uint32
	prot  uint32
	alloc uint32
}

func isSpaceSeparatedHex(s string) bool {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		_, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return false
		}
	}
	return true
}

var RV uintptr

func (p *Luna) GetRenderView(AOB_HexArray string) uintptr {

	if RV != 0 {
		return RV
	}

	if !isSpaceSeparatedHex(AOB_HexArray) {
		hexCodes := make([]string, len(AOB_HexArray))
		for i, c := range AOB_HexArray {
			hexCodes[i] = fmt.Sprintf("%X", c)
		}
		AOB_HexArray = strings.Join(hexCodes, " ")
	}

	pattern := p.PLAT(AOB_HexArray)
	var regions []MemoryReg
	var mbi windows.MemoryBasicInformation
	address := uintptr(0)

	for {
		err := windows.VirtualQueryEx(windows.Handle(p.ProcessHandle), address, &mbi, unsafe.Sizeof(mbi))
		if err != nil {
			break
		}
		if mbi.State == 0x1000 && mbi.Protect == 0x04 && mbi.AllocationProtect == 0x04 {
			regions = append(regions, MemoryReg{
				base:  address,
				size:  mbi.RegionSize,
				state: mbi.State,
				prot:  mbi.Protect,
				alloc: mbi.AllocationProtect,
			})
		}
		address += mbi.RegionSize
	}

	if len(regions) == 0 {
		return 0
	}

	resultsCh := make(chan []uintptr, len(regions))
	errCh := make(chan error, len(regions))

	var wg sync.WaitGroup
	wg.Add(len(regions))

	for _, region := range regions {
		go func(r MemoryReg) {
			defer wg.Done()
			data, err := p.ReadMemory(r.base, r.size)
			if err != nil {
				errCh <- err
				resultsCh <- nil
				return
			}
			localResults := findAllPatterns(data, pattern, r.base)
			resultsCh <- localResults
		}(region)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
		close(errCh)
	}()

	for res := range resultsCh {
		if len(res) > 0 {
			for _, address := range res {
				rv, _ := p.ReadPointer(address + 0x1E8)
				if rv == 0 {
					continue
				}
				f, _ := p.ReadPointer(rv + 0x120)
				if f == 0 {
					continue
				}
				r, _ := p.ReadPointer(f + 0x1a8)
				if r == 0 {
					continue
				}
				name, _ := p.ReadRbxStr(r + 0x68)
				if name == "Ugc" || name == "Game" || name == "App" || name == "LuaApp" {
					RV = address
					return RV
				}
			}
		}
	}

	return 0
}

func (p *Luna) AOBSCANALL(AOB_HexArray string, xreturn_multiple bool, stop_at_value int) ([]uintptr, error) {

	if !isSpaceSeparatedHex(AOB_HexArray) {
		hexCodes := make([]string, len(AOB_HexArray))
		for i, c := range AOB_HexArray {
			hexCodes[i] = fmt.Sprintf("%X", c)
		}
		AOB_HexArray = strings.Join(hexCodes, " ")
	}

	pattern := p.PLAT(AOB_HexArray)
	var results []uintptr

	var regions []MemoryReg
	var mbi windows.MemoryBasicInformation
	address := uintptr(0)

	for {
		err := windows.VirtualQueryEx(windows.Handle(p.ProcessHandle), address, &mbi, unsafe.Sizeof(mbi))
		if err != nil {
			break
		}
		if (mbi.State&windows.MEM_COMMIT) != 0 &&
			((mbi.Protect&windows.PAGE_READONLY) != 0 ||
				(mbi.Protect&windows.PAGE_READWRITE) != 0 ||
				(mbi.Protect&windows.PAGE_EXECUTE_READ) != 0 ||
				(mbi.Protect&windows.PAGE_EXECUTE_READWRITE) != 0) {
			//if mbi.State == 0x1000 && mbi.Protect == 0x04 && mbi.AllocationProtect == 0x04 {
			regions = append(regions, MemoryReg{
				base:  address,
				size:  mbi.RegionSize,
				state: mbi.State,
				prot:  mbi.Protect,
				alloc: mbi.AllocationProtect,
			})
		}
		address += mbi.RegionSize
	}

	if len(regions) == 0 {
		return nil, fmt.Errorf("no readable memory regions found")
	}

	resultsCh := make(chan []uintptr, len(regions))
	errCh := make(chan error, len(regions))

	var wg sync.WaitGroup
	wg.Add(len(regions))

	for _, region := range regions {
		go func(r MemoryReg) {
			defer wg.Done()
			data, err := p.ReadMemory(r.base, r.size)
			if err != nil {
				errCh <- err
				resultsCh <- nil
				return
			}
			if xreturn_multiple {
				localResults := findAllPatterns(data, pattern, r.base)
				resultsCh <- localResults
			} else {
				singleResult := findPattern(data, pattern, r.base)
				if singleResult != 0 {
					resultsCh <- []uintptr{singleResult}
				} else {
					resultsCh <- nil
				}
			}
		}(region)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
		close(errCh)
	}()

	for res := range resultsCh {
		if len(res) > 0 {
			if !xreturn_multiple {
				results = append(results, res[0])
				break
			}
			for _, addr := range res {
				results = append(results, addr)
				if stop_at_value > 0 && len(results) >= stop_at_value {
					break
				}
			}
			if stop_at_value > 0 && len(results) >= stop_at_value {
				break
			}
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })

	return results, nil
}
