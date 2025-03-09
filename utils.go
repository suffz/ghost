package main

import (
	"fmt"
	"main/packages/Memory/instance"
	"main/packages/Memory/memory"
	"main/packages/Memory/process_monitor"
	"main/packages/Memory/taskschedular"
	"main/packages/Memory/utils"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/jedib0t/go-pretty/table"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
)

var Active *instance.RobloxInstances
var First bool
var Roblox []*instance.RobloxInstances
var Patches map[uint32]bool = make(map[uint32]bool)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
)

func init() {

	go func() {
		ok, pid := memory.IsProcessRunning()
		if ok {
			var WG sync.WaitGroup
			for _, instances := range pid {
				WG.Add(1)
				go func(instances memory.Processes) {
					defer WG.Done()

					mem, err := memory.NewLuna(instances.Pid)
					if err != nil || mem == nil {
						return
					}

					if !Patches[instances.Pid] {
						instance.PatchRoblox(mem)
						fmt.Printf("[%v] Roblox succesfully patched.\n", instances.Pid)
						Patches[instances.Pid] = true
					}

					ok, err := process_monitor.IsProcessWindowInTaskbar(instances.Pid, false)
					p, _ := process.NewProcess(int32(instances.Pid))
					cpuUsage, _ := p.CPUPercent()
					if cpuUsage < 0.65 && !ok || err != nil {
						fmt.Printf("[%v] has been disconnected for: Ghost Process\n", instances.Pid)
						p.Kill()
						return
					}

					SaveInstance(instances, mem, false)

				}(instances)
			}
			WG.Wait()
			if len(Roblox) > 0 && Active == nil {
				Active = Roblox[0]
			}
		}
	}()
}

var SaveInstance = func(instances memory.Processes, mem *memory.Luna, ole bool) *instance.RobloxInstances {

	var renderview []uintptr

	for i := 0; i < 4; i++ {
		renderview, _ = mem.AOBSCANALL("RenderJob(EarlyRendering;", true, 2)
		if len(renderview) > 0 {
			break
		}
		time.Sleep(time.Second)
	}

	if len(renderview) == 0 {
		ok, _ := process_monitor.IsProcessWindowInTaskbar(mem.Pid, false)
		p, _ := process.NewProcess(int32(mem.Pid))
		cpuUsage, _ := p.CPUPercent()
		if cpuUsage < 0.65 && !ok {
			p.Kill()
			fmt.Printf("[%v] has been disconnected for: Ghost Process\n", instances.Pid)
			return nil
		}
		return nil
	}

	if len(renderview) > 0 {

		fmt.Printf("[%v] Fetched renderjob 0x%x\n", instances.Pid, renderview[0])

		var New *instance.RobloxInstances = &instance.RobloxInstances{
			Pid:     int64(instances.Pid),
			ExeName: instances.Name,
			Mem:     mem,
			Instances: instance.Instances{
				RobloxBase: uint64(mem.RobloxBase),
			},
			Offsets: utils.OffsetsDataPlayer,
		}

		rv, _ := mem.ReadPointer(renderview[0] + uintptr(New.Offsets.RenderViewFromRenderJob))
		New.Instances.RenderView = uint64(rv)

		fakedm, _ := mem.ReadPointer(rv + uintptr(New.Offsets.DataModelHolder))
		realdm, _ := mem.ReadPointer(fakedm + uintptr(New.Offsets.DataModel))
		DM := instance.NewInstance(realdm, New)

		if DM.Address < 1000 {
			return nil
		}

		Roblox = append(Roblox, New)

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"#", "Name", "Address", "RTTI"})

		for i, job := range taskschedular.GetTasks(New.Mem, taskschedular.GetSchedularFromRenderView(New.Mem, fakedm)) {
			name, _ := memory.RTTIInformation(mem, job.Address)
			t.AppendRow(table.Row{i + 1, job.Name, fmt.Sprintf("0x%x", job.Address), name})
		}
		t.Render()

		go DataModelHandler(New)
		return New
	}

	return nil
}

func DataModelHandler(RV *instance.RobloxInstances) {

	go func(RV *instance.RobloxInstances) {
		kill := func() {
			RV.Error = true
			syscall.CloseHandle(RV.Mem.ProcessHandle)
			p, _ := process.NewProcess(int32(RV.Pid))
			p.Kill()
		}
		checktime := func() float64 {
			proc, err := process.NewProcess(int32(RV.Pid))
			if err != nil {
				return 0
			}
			roblox_creation, err := proc.CreateTime()
			if err != nil {
				return 0
			}
			return time.Since(time.Unix(roblox_creation/1000, (roblox_creation%1000)*1000000)).Seconds()
		}
	Exit:
		for !RV.Error {
			if checktime() > 4 {
				rv, _ := RV.Mem.ReadPointer(uintptr(RV.Instances.RenderView) + uintptr(RV.Offsets.DataModelHolder))
				realdm, _ := RV.Mem.ReadPointer(rv + uintptr(RV.Offsets.DataModel))
				if rv == 0 && realdm == 0 {
					ok, _ := process_monitor.IsProcessWindowInTaskbar(uint32(RV.Pid), false)
					if !ok {
						kill()
						break Exit
					}
				}
				DM := instance.NewInstance(realdm, RV)
				switch DM.Name() {
				case "Game", "Ugc", "App", "LuaApp":
				default:
					kill()
					break Exit
				}
			}
			time.Sleep(time.Second)
		}

	}(RV)

	for !RV.Error {
		r, _, _ := procWaitForSingleObject.Call(uintptr(RV.Mem.ProcessHandle), 0xFFFFFFFF)
		if r == 0 {
			syscall.CloseHandle(RV.Mem.ProcessHandle)
			RV.Error = true
			RV.Injected = false
			fmt.Printf("[%v] has been disconnected for: Roblox Closure\n", RV.Pid)
		}
	}
}
