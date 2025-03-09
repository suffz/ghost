package taskschedular

/*
⠀⠀⠀⣠⣾⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣷⣄⠀
⠀⠀⠀⣿⣿⡇⠀⠀⢸⣿⢰⣿⡆⠀⣾⣿⡆⠀⣾⣷⠀⣿⣿⡇⠀⠀⢸⣿⣿⠀
⠀⠀⠀⣿⣿⡇⠀⠀⢸⣿⠘⣿⣿⣤⣿⣿⣿⣤⣿⡇⠀⢻⣿⡇⠀⠀⢸⣿⣿⠀
⠀⠀⠀⣿⣿⡇⠀⠀⢸⡿⠀⢹⣿⣿⣿⣿⣿⣿⣿⠁⠀⢸⣿⣇⠀⠀⢸⣿⣿⠀
⠀⠀⠀⠙⢿⣷⣶⣶⡿⠁⠀⠈⣿⣿⠟⠀⣿⣿⠇⠀⠀⠈⠻⣿⣿⣿⣿⡿⠋
*/

import (
	"fmt"
	"main/packages/Memory/memory"
	"strings"
	"unicode"
)

type Schedular struct {
	Name    string
	Address uintptr
}

var (
	JobPointer = uintptr(0x918)
	JobHolder  = uintptr(0x10)
	JobState   = uintptr(0x8)
	Jobs       = uintptr(0x30)
	Container  = uintptr(0x120)
	DataModel  = uintptr(0x1a8)
)

func isvalidname(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
		if !(r == ' ' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func GetTasks(mem *memory.Luna, Task uintptr) (data []Schedular) {
	for i := 0x8; i < 0x300; i += 0x18 {
		T, _ := mem.ReadPointer(Task + uintptr(i))
		owo, _ := mem.ReadPointer(T + 0x90)
		if owo == 0 {
			break
		}
		if fmt.Sprintf("%v", owo)[0] != fmt.Sprintf("%v", T)[0] {
			owo = T + 0x90
		}
		if yas, _ := mem.ReadString(owo, 0); yas != "" && !strings.Contains(yas, "\n") && isvalidname(yas) {
			data = append(data, Schedular{
				Name:    yas,
				Address: T,
			})
		}
	}
	return
}

func GetSchedularFromDatamodel(mem *memory.Luna, DM uintptr) uintptr {
	job, _ := mem.ReadPointer(DM + JobPointer)
	jobs, _ := mem.ReadPointer(job + JobHolder)
	container, _ := mem.ReadPointer(jobs + JobState)
	lol, _ := mem.ReadPointer(container + Jobs)
	return lol
}

func GetSchedularFromRenderView(mem *memory.Luna, RV uintptr) uintptr {
	job, _ := mem.ReadPointer(RV + Jobs)
	return job
}

func GetDataModelFromRenderView(mem *memory.Luna, RV uintptr) uintptr {
	container, _ := mem.ReadPointer(RV + Container)
	dm, _ := mem.ReadPointer(container + DataModel)
	return dm
}

func GetContainerFromRenderView(mem *memory.Luna, RV uintptr) uintptr {
	container, _ := mem.ReadPointer(RV + Container)
	return container
}
