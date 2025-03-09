package main

import (
	"fmt"
	"main/packages/Memory/instance"
	"main/packages/Memory/memory"
	"main/packages/Memory/process_monitor"
	rt "runtime"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/shirou/gopsutil/process"
)

func main() {

	fmt.Println(`
 **                                 
/**                                 
/**       **   ** *******   ******  
/**      /**  /**//**///** //////** 
/**      /**  /** /**  /**  ******* 
/**      /**  /** /**  /** **////** 
/********//****** ***  /**//********
////////  ////// ///   //  //////// 
`)

	rt.LockOSThread()
	defer rt.UnlockOSThread()

	if err := ole.CoInitialize(0); err == nil {
		defer ole.CoUninitialize()

		unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
		if err == nil {
			locator, err := unknown.QueryInterface(ole.IID_IDispatch)
			if err == nil {
				defer locator.Release()
				serviceRaw, err := oleutil.CallMethod(locator, "ConnectServer", nil, "root\\cimv2")
				if err == nil {
					service := serviceRaw.ToIDispatch()
					defer service.Release()
					query := "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND (TargetInstance.Name = 'RobloxPlayerBeta.exe' OR TargetInstance.Name = 'eurotrucks2.exe' OR TargetInstance.Name = 'Windows10Universal.exe')"
					eventSourceRaw, err := oleutil.CallMethod(service, "ExecNotificationQuery", query)
					if err == nil {
						eventSource := eventSourceRaw.ToIDispatch()
						defer eventSource.Release()
						for {
							eventRaw, err := oleutil.CallMethod(eventSource, "NextEvent", 10000)
							if err != nil {
								time.Sleep(500 * time.Millisecond)
								continue
							}
							event := eventRaw.ToIDispatch()

							targetInstanceRaw, err := oleutil.GetProperty(event, "TargetInstance")
							if err != nil {
								event.Release()
								continue
							}

							targetInstance := targetInstanceRaw.ToIDispatch()

							nameVar, err := oleutil.GetProperty(targetInstance, "Name")
							if err != nil {
								targetInstance.Release()
								event.Release()
								continue
							}

							pidVar, err := oleutil.GetProperty(targetInstance, "ProcessId")
							if err != nil {
								nameVar.Clear()
								targetInstance.Release()
								event.Release()
								continue
							}

							go func(pid uint32, name string) {

								mem, err := memory.NewLuna(pid)
								if err != nil || mem == nil {
									return
								}

								if !Patches[pid] {
									instance.PatchRoblox(mem)
									Patches[pid] = true
									fmt.Printf("[%v] Roblox succesfully patched.\n", pid)
								}

								time.Sleep(time.Second * 3)
								ok, _ := process_monitor.IsProcessWindowInTaskbar(pid, false)

								p, _ := process.NewProcess(int32(pid))
								cpuUsage, _ := p.CPUPercent()
								if cpuUsage < 0.65 && !ok {
									p.Kill()
									return
								}

								if New := SaveInstance(memory.Processes{
									Name: name,
									Pid:  pid,
								}, mem, true); New != nil {
									if Active == nil {
										Active = New
									}
								}

							}(uint32(pidVar.Val), nameVar.ToString())

							nameVar.Clear()
							pidVar.Clear()
							targetInstance.Release()
							event.Release()
						}
					}
				}
			}
		}
	}
}
