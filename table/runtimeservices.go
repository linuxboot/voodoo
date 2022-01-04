package table

const (
	RTHdr                       = 0
	RTGetTime                   = 0x18
	RTSetTime                   = 0x20
	RTGetWakeupTime             = 0x28
	RTSetWakeupTime             = 0x30
	RTSetVirtualAddressMap      = 0x38
	RTConvertPointer            = 0x40
	RTGetVariable               = 0x48
	RTGetNextVariableName       = 0x50
	RTSetVariable               = 0x58
	RTGetNextHighMonotonicCount = 0x60
	RTResetSystem               = 0x68
	RTUpdateCapsule             = 0x70
	RTQueryCapsuleCapabilities  = 0x78
	RTQueryVariableInfo         = 0x80
)

var RuntimeServicesNames = map[uint64]*val{
	RTHdr:                       {N: "Hdr"},
	RTGetTime:                   {N: "GetTime"},
	RTSetTime:                   {N: "SetTime"},
	RTGetWakeupTime:             {N: "GetWakeupTime"},
	RTSetWakeupTime:             {N: "SetWakeupTime"},
	RTSetVirtualAddressMap:      {N: "SetVirtualAddressMap"},
	RTConvertPointer:            {N: "ConvertPointer"},
	RTGetVariable:               {N: "GetVariable"},
	RTGetNextVariableName:       {N: "GetNextVariableName"},
	RTSetVariable:               {N: "SetVariable"},
	RTGetNextHighMonotonicCount: {N: "GetNextHighMonotonicCount"},
	RTResetSystem:               {N: "ResetSystem"},
	RTUpdateCapsule:             {N: "UpdateCapsule"},
	RTQueryCapsuleCapabilities:  {N: "QueryCapsuleCapabilities"},
	RTQueryVariableInfo:         {N: "QueryVariableInfo"},
}

type EfiTime struct {
	Year       uint16
	Month      uint8
	Day        uint8
	Hour       uint8
	Minute     uint8
	Second     uint8
	_          uint8
	Nanosecond uint32
	Timezone   int16
	Daylight   uint8
	_          uint8
}
type EfiTimeCap struct {
	Resolution uint32
	Accuracy   uint32
	SetsToZero uint8
}
