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
	RTHdr:                       &val{N: "Hdr"},
	RTGetTime:                   &val{N: "GetTime"},
	RTSetTime:                   &val{N: "SetTime"},
	RTGetWakeupTime:             &val{N: "GetWakeupTime"},
	RTSetWakeupTime:             &val{N: "SetWakeupTime"},
	RTSetVirtualAddressMap:      &val{N: "SetVirtualAddressMap"},
	RTConvertPointer:            &val{N: "ConvertPointer"},
	RTGetVariable:               &val{N: "GetVariable"},
	RTGetNextVariableName:       &val{N: "GetNextVariableName"},
	RTSetVariable:               &val{N: "SetVariable"},
	RTGetNextHighMonotonicCount: &val{N: "GetNextHighMonotonicCount"},
	RTResetSystem:               &val{N: "ResetSystem"},
	RTUpdateCapsule:             &val{N: "UpdateCapsule"},
	RTQueryCapsuleCapabilities:  &val{N: "QueryCapsuleCapabilities"},
	RTQueryVariableInfo:         &val{N: "QueryVariableInfo"},
}
