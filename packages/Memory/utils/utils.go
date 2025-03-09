package utils

type Offsets struct {
	RenderViewFromRenderJob uint64
	DataModelHolder         uint64
	DataModel               uint64

	Name            uint64
	Children        uint64
	Parent          uint64
	ClassDescriptor uint64

	ValueBase   uint64
	ModuleFlags uint64
	IsCore      uint64

	LocalPlayer uintptr

	GameIsLoaded uint64

	Bytecode map[string]uint64
}

var OffsetsDataPlayer = Offsets{
	RenderViewFromRenderJob: 0x1e8,
	DataModelHolder:         0x120,
	DataModel:               0x1a8,

	Name:            0x68,
	Children:        0x70,
	Parent:          0x50,
	ClassDescriptor: 0x18,
	ValueBase:       0xc8,

	ModuleFlags: 0x1b0 - 0x4,
	IsCore:      0x1b0,

	GameIsLoaded: 0x628,

	LocalPlayer: 0x118,

	Bytecode: map[string]uint64{
		"LocalScript":  0x1c0,
		"ModuleScript": 0x168,
	},
}

var OffsetsDataUwp = Offsets{
	RenderViewFromRenderJob: 0x1e8,
	DataModelHolder:         0x120,
	DataModel:               0x1a8,

	Name:            0x68,
	Children:        0x70,
	Parent:          0x50,
	ClassDescriptor: 0x18,
	ValueBase:       0xc8,

	ModuleFlags: 0x1b0 - 0x4,
	IsCore:      0x1b0,

	LocalPlayer: 0x118,

	GameIsLoaded: 0x620,

	Bytecode: map[string]uint64{
		"LocalScript":  0x1c0,
		"ModuleScript": 0x168,
	},
}
