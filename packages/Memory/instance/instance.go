package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"main/packages/Memory/classdescriptor"
	"main/packages/Memory/memory"
	"main/packages/Memory/taskschedular"
	"main/packages/Memory/utils"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

type Instance struct {
	Address uintptr
	Mem     *RobloxInstances
}

type RobloxInstances struct {
	Error    bool
	Injected bool
	Username string
	Pid      int64
	ExeName  string
	Uwp      bool
	//Ingame    bool
	Inmenu      bool
	Avatar      string
	Mem         *memory.Luna
	Instances   Instances
	Offsets     utils.Offsets
	Capabilitys []Modules
	Queue       []string
}
type Instances struct {
	RenderView uint64
	RobloxBase uint64
}

type Modules struct {
	Name     string
	Address  uint64
	LuaState uint64
}

type Level8 struct {
	CoreGuiContainer, CoreGuiToModules, ModulesToInstances, InstancesToChildren, ModuleScript uint64
	//
	ToIdentity, ToCapabilities, LuaState uint64
}

var Offsets Level8 = Level8{
	CoreGuiContainer:    0x390,
	CoreGuiToModules:    0x8,
	ModulesToInstances:  0x78,
	InstancesToChildren: 0x10,
	ModuleScript:        0x50,

	ToIdentity:     0x30,
	ToCapabilities: 0x48,
	LuaState:       0x650,
}

func NewInstance(address uintptr, Mem *RobloxInstances) Instance {
	return Instance{
		Address: address,
		Mem:     Mem,
	}
}

func (inst *Instance) ClassDescriptor() *classdescriptor.ClassDescriptor {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return &classdescriptor.ClassDescriptor{}
	}

	mem := inst.Mem.Mem

	addr, _ := mem.ReadPointer(inst.Address + uintptr(inst.Mem.Offsets.ClassDescriptor))
	return classdescriptor.NewClassDescriptor(addr)
}

func (inst *Instance) ClassName() string {
	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return "None"
	}

	mem := inst.Mem.Mem

	return inst.ClassDescriptor().Name(mem)
}

func (inst *Instance) Name() string {
	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return "None"
	}

	mem := inst.Mem.Mem

	namePointer, _ := mem.ReadPointer(inst.Address + uintptr(inst.Mem.Offsets.Name))
	name, _ := mem.ReadRbxStr(namePointer)
	return name
}

func (inst *Instance) Parent() Instance {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return NewInstance(0, nil)
	}

	mem := inst.Mem.Mem

	parentAddr, _ := mem.ReadPointer(inst.Address + uintptr(inst.Mem.Offsets.Parent))
	return NewInstance(parentAddr, inst.Mem)
}

func (inst *Instance) LocalPlayer() Instance {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return NewInstance(0, inst.Mem)
	}

	mem := inst.Mem.Mem

	if inst.Address < 1000 {
		return NewInstance(0, inst.Mem)
	}
	localplayer, _ := mem.ReadPointer(inst.Address + uintptr(inst.Mem.Offsets.LocalPlayer))
	return NewInstance(localplayer, inst.Mem)
}

func (inst *Instance) GetChildren() (Data []Instance) {
	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return []Instance{NewInstance(0, inst.Mem)}
	}

	mem := inst.Mem.Mem

	childrenPointer, _ := mem.ReadPointer(inst.Address + uintptr(inst.Mem.Offsets.Children))
	top, _ := mem.ReadPointer(childrenPointer)
	end, _ := mem.ReadPointer(childrenPointer + 0x8)
	var ContinueIfFound bool
	for childAddr := top; childAddr < end; childAddr += 0x10 {
		if ContinueIfFound {
			ContinueIfFound = false
			continue
		}
		childPtr, _ := mem.ReadPointer(childAddr)
		if childPtr < 1000 {
			continue
		}
		child := NewInstance(childPtr, inst.Mem)
		n := child.Name()
		if n == "MarketplaceService" {
			ContinueIfFound = true
			continue
		}
		Data = append(Data, child)
	}
	return Data
}

func (inst *Instance) GetTaskSchedular() {

}

func (inst *Instance) GetParentPatternString() string {
	var history []Instance
	var wtf []string
	var new = *inst
	for {
		if new.Name() == "None" {
			break
		}
		history = append(history, new)
		new = new.Parent()
	}
	slices.Reverse(history)
	for _, instance := range history {
		name := instance.Name()
		if name == "Ugc" || name == "Game" || name == "LuaApp" || name == "App" {
			name = "game"
		}
		wtf = append(wtf, name)
	}
	return strings.Join(wtf, ".")
}

func mostFrequentUint64(nums []uint64) (uint64, int) {
	frequencyMap := make(map[uint64]int)
	for _, num := range nums {
		frequencyMap[num]++
	}
	var mostFrequentNum uint64
	maxFrequency := 0
	for num, count := range frequencyMap {
		if count > maxFrequency {
			maxFrequency = count
			mostFrequentNum = num
		}
	}

	return mostFrequentNum, maxFrequency
}

func (inst *Instance) GetIdentity(timeout int, className ...string) uint64 {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return 8
	}

	var (
		Identities []uint64
		Modules    []Modules
	)

	mem := inst.Mem.Mem

	if len(inst.Mem.Capabilitys) > 0 {
		Modules = inst.Mem.Capabilitys
	} else {
		Modules = inst.GetRunningScripts(timeout, className...)
		inst.Mem.Capabilitys = Modules
	}

	if len(Modules) > 0 {
		for _, Module := range Modules {
			var identity int
			mem.MemRead(uintptr(Module.LuaState+Offsets.ToIdentity), unsafe.Pointer(&identity), unsafe.Sizeof(identity))
			Identities = append(Identities, uint64(identity))
		}
	}
	most, _ := mostFrequentUint64(Identities)
	return most
}

func (inst *Instance) GetRunningScripts(timeout int, className ...string) (M []Modules) {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return
	}

	mem := inst.Mem.Mem
	var ToAdd map[uint64]Modules = make(map[uint64]Modules)
	for i := 0; i < timeout*10; i++ {
		var (
			PointerToList      uint64
			PointerToModules   uint64
			PointerToInstances uint64
			Looping            uint64
			BlankCounter       = 0
			ModulePointer      uint64
			ModuleScript       uint64
		)

		// find jestglobals
		mem.MemRead(inst.Address+uintptr(Offsets.CoreGuiContainer), unsafe.Pointer(&PointerToList), unsafe.Sizeof(PointerToList))
		mem.MemRead(uintptr(PointerToList+Offsets.CoreGuiToModules), unsafe.Pointer(&PointerToModules), unsafe.Sizeof(PointerToModules))
		mem.MemRead(uintptr(PointerToModules+Offsets.ModulesToInstances), unsafe.Pointer(&PointerToInstances), unsafe.Sizeof(PointerToInstances))
		mem.MemRead(uintptr(PointerToInstances+Offsets.InstancesToChildren), unsafe.Pointer(&Looping), unsafe.Sizeof(Looping))

		for i := 0x10; i < 0x10*1500; i = i + 0x10 {
			mem.MemRead(uintptr(Looping+0x10), unsafe.Pointer(&ModulePointer), unsafe.Sizeof(ModulePointer))

			Looping = ModulePointer
			mem.MemRead(uintptr(Looping+Offsets.ModuleScript), unsafe.Pointer(&ModuleScript), unsafe.Sizeof(ModuleScript))
			Module := NewInstance(uintptr(ModuleScript), inst.Mem)
			name := Module.Name()
			if name == "" {
				BlankCounter++
			} else {
				for _, classN := range className {
					if strings.Contains(name, classN) {
						ToAdd[ModulePointer] = Modules{
							Name:     classN,
							Address:  uint64(Module.Address),
							LuaState: ModulePointer,
						}
					}
				}
				if BlankCounter > 0 {
					BlankCounter = 0
				}
			}
			if BlankCounter >= 20 {
				break
			}
		}
		if len(ToAdd) > 0 {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}

	for _, value := range ToAdd {
		M = append(M, value)
	}

	return M
}

type Capability struct {
	value uint64
	shift bool
}

var allCapabilities = map[string]Capability{
	"Plugin":             {0x1, false},
	"LocalUser":          {0x2, false},
	"WritePlayer":        {0x4, false},
	"RobloxScript":       {0x8, false},
	"RobloxEngine":       {0x10, false},
	"NotAccessible":      {0x20, false},
	"RunClientScript":    {0x8, true},
	"RunServerScript":    {0x9, true},
	"AccessOutsideWrite": {0xb, true},
	"Unassigned":         {0xf, true},
	"AssetRequire":       {0x10, true},
	"LoadString":         {0x11, true},
	"ScriptGlobals":      {0x12, true},
	"CreateInstances":    {0x13, true},
	"Basic":              {0x14, true},
	"Audio":              {0x15, true},
	"DataStore":          {0x16, true},
	"Network":            {0x17, true},
	"Physics":            {0x18, true},
	"UI":                 {0x19, true},
	"CSG":                {0x1a, true},
	"Chat":               {0x1b, true},
	"Animation":          {0x1c, true},
	"Avatar":             {0x1d, true},
	"Input":              {0x1e, true},
	"Environment":        {0x1f, true},
	"RemoteEvent":        {0x20, true},
	"LegacySound":        {0x21, true},
	"PluginOrOpenCloud":  {0x3d, true},
	"Assistant":          {0x3e, true},
}

var identityCapabilities = map[int][]string{
	3: {"RunServerScript", "Plugin", "LocalUser", "RobloxScript", "RunClientScript", "AccessOutsideWrite", "Avatar", "RemoteEvent", "Environment", "Input", "LegacySound"},
	2: {"CSG", "Chat", "Animation", "RemoteEvent", "Avatar", "LegacySound"},
	4: {"Plugin", "LocalUser", "RemoteEvent", "Avatar", "LegacySound"},
	6: {"RunServerScript", "Plugin", "LocalUser", "Avatar", "RobloxScript", "RunClientScript", "AccessOutsideWrite", "Input", "Environment", "RemoteEvent", "PluginOrOpenCloud", "LegacySound"},
	7: {"Plugin", "LocalUser", "WritePlayer", "RobloxScript", "RobloxEngine", "NotAccessible", "RunClientScript", "RunServerScript", "AccessOutsideWrite", "Unassigned", "AssetRequire", "LoadString", "ScriptGlobals", "CreateInstances", "Basic", "Audio", "DataStore", "Network", "Physics", "UI", "CSG", "Chat", "Animation", "Avatar", "Input", "Environment", "RemoteEvent", "PluginOrOpenCloud", "Assistant", "LegacySound"},
	8: {"Plugin", "LocalUser", "WritePlayer", "RobloxScript", "RobloxEngine", "NotAccessible", "RunClientScript", "RunServerScript", "AccessOutsideWrite", "Unassigned", "AssetRequire", "LoadString", "ScriptGlobals", "CreateInstances", "Basic", "Audio", "DataStore", "Network", "Physics", "UI", "CSG", "Chat", "Animation", "Avatar", "Input", "Environment", "RemoteEvent", "PluginOrOpenCloud", "Assistant", "LegacySound"},
}

func IdentityToCapabilities(identity uint32) uint64 {
	capabilities := uint64(0x3FFFFFF00) | (1 << 48)

	if caps, ok := identityCapabilities[int(identity)]; ok {
		for _, capName := range caps {
			if cap, exists := allCapabilities[capName]; exists {
				if cap.shift {
					capabilities |= (1 << cap.value)
				} else {
					capabilities |= cap.value
				}
			}
		}
	}
	return capabilities
}

func (inst *Instance) ApplyCapacity(identity int, caps uint64, timeout int, className ...string) {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return
	}

	mem := inst.Mem.Mem

	var (
		Holder  uint64
		State   uint64
		NewCaps uint64 = caps
	)
	var Modules_ []Modules

	if len(inst.Mem.Capabilitys) != 0 {
		Modules_ = inst.Mem.Capabilitys
	} else {
		Modules_ = inst.GetRunningScripts(timeout, className...)
		inst.Mem.Capabilitys = Modules_
	}

	if len(Modules_) > 0 {
		//var w sync.WaitGroup
		for _, Modules := range Modules_ {
			//w.Add(1)
			//go func(Modules Modules) {
			//	defer w.Done()
			mem.MemWrite(uintptr(Modules.LuaState+Offsets.ToIdentity), unsafe.Pointer(&identity), unsafe.Sizeof(identity))
			mem.MemWrite(uintptr(Modules.LuaState+Offsets.ToCapabilities), unsafe.Pointer(&NewCaps), unsafe.Sizeof(NewCaps))
			//}(M)
		}
		//w.Wait()
		if len(inst.Mem.Capabilitys) == 0 {
			mem.MemRead(inst.Address+uintptr(Offsets.LuaState), unsafe.Pointer(&Holder), unsafe.Sizeof(Holder))
			mem.MemRead(uintptr(Holder+0x8), unsafe.Pointer(&State), unsafe.Sizeof(State))
			mem.MemWrite(uintptr(State+0x10), unsafe.Pointer(&NewCaps), unsafe.Sizeof(NewCaps))
			mem.MemWrite(uintptr(State+0x18), unsafe.Pointer(&NewCaps), unsafe.Sizeof(NewCaps))

			mem.MemRead(inst.Address+uintptr(Offsets.LuaState), unsafe.Pointer(&Holder), unsafe.Sizeof(Holder))
			mem.MemRead(uintptr(Holder), unsafe.Pointer(&State), unsafe.Sizeof(State))
			mem.MemWrite(uintptr(State+0x10), unsafe.Pointer(&NewCaps), unsafe.Sizeof(NewCaps))
			mem.MemWrite(uintptr(State+0x18), unsafe.Pointer(&NewCaps), unsafe.Sizeof(NewCaps))
		}
	}
}

func (inst *Instance) WaitForChild(name string, timeout int) Instance {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return NewInstance(0, inst.Mem)
	}

	for times := 0; times < timeout*10; times++ {
		child := inst.FindFirstChild(name, false)
		if child.Address != 0 {
			n := child.Name()
			if n == name {
				return child
			}
		}
		time.Sleep(time.Millisecond * time.Duration(100))
	}

	return Instance{Address: 0}
}

func (inst *Instance) WaitForClass(name string, timeout int) Instance {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return NewInstance(0, inst.Mem)
	}

	for times := 0; times < timeout*10; times++ {
		child := inst.FindFirstChildOfClass(name, false)
		if child.Address != 0 {
			n := child.ClassName()
			if n == name {
				return child
			}
		}
		time.Sleep(time.Millisecond * time.Duration(100))
	}

	return Instance{Address: 0}
}

func (inst *Instance) FindFirstChild(name string, recursive bool, ignore ...string) Instance {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return NewInstance(0, inst.Mem)
	}

	if slices.Contains(ignore, "Players") {
		ignore = append(ignore, "Players")
	}

	mem := inst.Mem.Mem

	childrenPointer, _ := mem.ReadPointer(inst.Address + uintptr(inst.Mem.Offsets.Children))
	top, _ := mem.ReadPointer(childrenPointer)
	end, _ := mem.ReadPointer(childrenPointer + mem.PointerSize()*2)

	for childAddr := top; childAddr < end; childAddr += mem.PointerSize() * 2 {
		childPtr, _ := mem.ReadPointer(childAddr)
		if childPtr < 1000 {
			continue
		}
		child := NewInstance(childPtr, inst.Mem)
		n := child.Name()
		if slices.Contains(ignore, n) && name != "Players" {
			continue
		}
		if n == name {
			return child
		}
		if recursive {
			descendantChild := child.FindFirstChild(name, true)
			if descendantChild.Address > 1000 {
				return descendantChild
			}
		}
	}
	return NewInstance(0, inst.Mem)
}

func (inst *Instance) GetByteCode() ([]byte, int64) {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return nil, 0
	}

	mem := inst.Mem.Mem

	var offset = inst.Mem.Offsets.Bytecode[inst.ClassName()]
	var size uintptr

	var btc_ptr uint64
	bytecode_pointer, _ := mem.ReadPointer(inst.Address + uintptr(offset))

	mem.MemRead(bytecode_pointer+0x10, unsafe.Pointer(&btc_ptr), unsafe.Sizeof(btc_ptr))
	mem.MemRead(bytecode_pointer+0x20, unsafe.Pointer(&size), unsafe.Sizeof(size))

	data, _ := mem.ReadBytes(uintptr(btc_ptr), size)
	return data, int64(size)
}

func (inst *Instance) SetBytecode(bytecode []byte, s uint64) {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return
	}

	mem := inst.Mem.Mem

	size := uintptr(s)
	bytecode_pointer, _ := mem.ReadPointer(inst.Address + uintptr(inst.Mem.Offsets.Bytecode[inst.ClassName()]))
	new_ptr, _ := mem.AllocateMemory(size)
	mem.WriteBytes(new_ptr, bytecode, size)
	mem.MemWrite(bytecode_pointer+0x10, unsafe.Pointer(&new_ptr), unsafe.Sizeof(new_ptr))
	mem.MemWrite(bytecode_pointer+0x20, unsafe.Pointer(&size), unsafe.Sizeof(size))
}

func (inst *Instance) FindFirstChildOfClass(className string, recursive bool, ignore ...string) Instance {
	if inst == nil || inst.Mem == nil {
		return NewInstance(0, inst.Mem)
	}
	if slices.Contains(ignore, "Players") {
		ignore = append(ignore, "Players")
	}
	mem := inst.Mem.Mem
	childrenPointer, err := mem.ReadPointer(inst.Address + uintptr(inst.Mem.Offsets.Children))
	if err != nil {
		return NewInstance(0, inst.Mem)
	}
	top, err := mem.ReadPointer(childrenPointer)
	if err != nil {
		return NewInstance(0, inst.Mem)
	}
	end, err := mem.ReadPointer(childrenPointer + mem.PointerSize())
	if err != nil {
		return NewInstance(0, inst.Mem)
	}
	for childAddr := top; childAddr < end; childAddr += mem.PointerSize() * 2 {
		childPtr, _ := mem.ReadPointer(childAddr)
		if childPtr < 1000 {
			continue
		}
		child := NewInstance(childPtr, inst.Mem)
		n := child.ClassName()
		if slices.Contains(ignore, n) && n != "Players" {
			continue
		}
		if n == className {
			return child
		}
		if recursive {
			descendantChild := child.FindFirstChildOfClass(className, true)
			if descendantChild.Address > 1000 {
				return descendantChild
			}
		}
	}
	return NewInstance(0, inst.Mem)
}

func (inst *Instance) SetModuleBypass() {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return
	}

	mem := inst.Mem.Mem

	var set uint64 = 0x100000000
	var core uint64 = 0x1
	mem.MemWrite(inst.Address+uintptr(inst.Mem.Offsets.ModuleFlags), unsafe.Pointer(&set), unsafe.Sizeof(set))
	mem.MemWrite(inst.Address+uintptr(inst.Mem.Offsets.IsCore), unsafe.Pointer(&core), unsafe.Sizeof(core))
}

func (inst *Instance) Value() interface{} {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return 0
	}

	mem := inst.Mem.Mem

	className := inst.ClassName()
	switch className {
	case "BoolValue":
		val, _ := mem.ReadByte(inst.Address + uintptr(inst.Mem.Offsets.ValueBase))
		return val == 1
	case "NumberValue":
		val, _ := mem.ReadDouble(inst.Address + uintptr(inst.Mem.Offsets.ValueBase))
		return val
	case "ObjectValue":
		addr, _ := mem.ReadPointer(inst.Address + uintptr(inst.Mem.Offsets.ValueBase))
		return NewInstance(addr, inst.Mem)
	case "StringValue", "":
		stringPointer := inst.Address + uintptr(inst.Mem.Offsets.ValueBase)
		stringLength, err := mem.ReadInt32(stringPointer + 0x10)
		if stringLength == 0 {
			return err
		}
		if stringLength > 15 {
			data, _ := mem.ReadInt32(stringPointer)
			stringPointer = uintptr(data)
		}
		str, _ := mem.ReadString(stringPointer, uintptr(stringLength))
		return str
	default:
		return nil
	}
}

func (inst *Instance) SetValue(value interface{}) {

	if inst == nil || inst.Mem == nil || inst.Mem.Mem == nil || inst.Address < 1000 {
		return
	}

	mem := inst.Mem.Mem
	className := inst.ClassName()

	switch className {
	case "BoolValue":
		val := byte(0)
		if value.(bool) {
			val = 1
		}
		mem.WriteByte(inst.Address+uintptr(inst.Mem.Offsets.ValueBase), val)
	case "NumberValue":
		mem.WriteDouble(inst.Address+uintptr(inst.Mem.Offsets.ValueBase), float64(value.(int)))
	case "ObjectValue":
		var addr uintptr
		if value != nil {
			addr = value.(*Instance).Address
		}
		mem.WritePointer(inst.Address+uintptr(inst.Mem.Offsets.ValueBase-0x8), addr)
	case "StringValue":
		stringAddr := inst.Address + uintptr(inst.Mem.Offsets.ValueBase)
		stringLength, _ := mem.ReadInt32(stringAddr + 0x10)
		var redirectedPtr uintptr
		if stringLength > 15 {
			val, _ := mem.ReadPointer(stringAddr)
			redirectedPtr = val
		} else {
			redirectedPtr = stringAddr
		}
		mem.WriteString(redirectedPtr, value.(string))
		mem.WriteInt32(stringAddr+0x10, int32(len(value.(string))+1))
	}
}

func (inst *Instance) String() string {
	return "(" + inst.Name() + " as " + inst.ClassName() + " | " + fmt.Sprintf("%#x", inst.Address) + ")"
}

func GetHyperionVersion(Memory *memory.Luna) string {
	datamodel, _ := Memory.AOBSCANALL("48 59 50 56", false, 1)
	fmt.Println(datamodel)
	for _, addr := range datamodel {
		ver, _ := Memory.ReadString(addr, 100)
		if strings.Contains(ver, ".") {
			return ver
		}
	}

	return ""
}

func GetLoopbackExemption(wildCard string) error {
	cmd := exec.Command("CheckNetIsolation.exe", "LoopbackExempt", "-a", fmt.Sprintf(`-n="%v"`, wildCard))

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	return cmd.Run()
}

type PackageInfo struct {
	Name              string `json:"Name"`
	PackageFamilyName string `json:"PackageFamilyName"`
}

func GetPackageFamilyName(appWildcard string) (string, error) {
	cmdStr := fmt.Sprintf("Get-AppxPackage -Name *%s* | Select Name, PackageFamilyName | ConvertTo-Json", appWildcard)
	cmd := exec.Command("powershell", "-Command", cmdStr)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("command failed: %w, output: %s", err, out.String())
	}
	output := out.Bytes()
	var packages []PackageInfo
	if err := json.Unmarshal(output, &packages); err != nil {
		var single PackageInfo
		if err2 := json.Unmarshal(output, &single); err2 != nil {
			return "", fmt.Errorf("json unmarshal error: %w", err2)
		}
		return single.PackageFamilyName, nil
	}
	if len(packages) > 0 {
		return packages[0].PackageFamilyName, nil
	}
	return "", fmt.Errorf("no package found")
}

func PatchUwp() {
	go func() {
		if wildCard, err := GetPackageFamilyName("ROBLOXCORPORATION.ROBLOX"); err == nil {
			GetLoopbackExemption(wildCard)
		}
	}()
}

var RV uintptr

func GetRenderviewAllocMethod(mem *memory.Luna, New *RobloxInstances) uintptr {
	if RV != 0 {
		return RV
	}
	if mem == nil {
		return 0
	}
	if len(mem.InstanceContainer) == 0 {
		fmt.Println("erm")
		return 0
	}

	foundChan := make(chan Instance, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup

	getDM := func(f uintptr) Instance {
		dm, _ := mem.ReadPointer(f + 0x50)
		if dm != 0 {
			candidate := NewInstance(dm, New)
			if name := candidate.Name(); name == "LuaApp" || name == "App" || name == "Game" || name == "Ugc" {
				return candidate
			}
		}
		return Instance{Address: 0}
	}

	for _, addr := range mem.InstanceContainer {
		wg.Add(1)
		go func(addr uintptr) {
			defer wg.Done()
			for i := 2000; i < 0x1000; i += 0x8 {
				select {
				case <-ctx.Done():
					return
				default:
				}
				test, _ := mem.ReadPointer(addr + uintptr(i))
				f := NewInstance(test, New)
				if n := f.Name(); n != "None" && n != "" {
					switch n {
					case "Workspace", "ReplicatedFirst", "StarterPlayer", "JointsService":
						candidate := getDM(f.Address)
						if candidate.Address != 0 {
							select {
							case foundChan <- candidate:
								cancel()
								return
							default:
							}
						}
					}
				}
			}
		}(addr)
	}

	go func() {
		wg.Wait()
		close(foundChan)
	}()

	var DM Instance
	if candidate, ok := <-foundChan; ok {
		DM = candidate
	} else {
		DM = Instance{Address: 0}
	}

	for _, job := range taskschedular.GetTasks(mem,
		taskschedular.GetSchedularFromDatamodel(mem, DM.Address),
	) {
		switch job.Name {
		case "RenderJob":
			rv, _ := mem.ReadPointer(job.Address + 0x218) // 0x218 == RenderView
			RV = rv
			return rv
		}
	}

	return 0

}

func PatchRoblox(Memory *memory.Luna) bool {
	if Memory == nil {
		return false
	}
	proc, err := process.NewProcess(int32(Memory.Pid))
	if err != nil {
		return false
	}
	roblox_creation, err := proc.CreateTime()
	if err != nil {
		return false
	}
	if time.Since(time.Unix(roblox_creation/1000, (roblox_creation%1000)*1000000)).Seconds() > 2 {
		return false
	}

	for i := 0; i < 50; i++ {
		if regions, err := Memory.QueryMemoryRegions(); err == nil {
			for i, region := range regions {
				if region.Protect == windows.PAGE_READWRITE && region.Size == 0x200000 {
					var ptr = region.BaseAddress + 0x208
					val, err := Memory.ReadUint64(ptr)
					Memory.AllocAddr = region.BaseAddress

					for _, r := range regions[i-5 : i] {
						Memory.InstanceContainer = append(Memory.InstanceContainer, r.BaseAddress)
					}

					if err == nil && int64(val) != 32 {
						Memory.WritePointer(ptr, 0x20)
					}
					return true
				}
			}
		} else {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
