package table

// These are the offsets of various UEFI boot services.
const (
	BootServicesOffset                  = 0x60
	RaiseTPL                            = 0x18
	RestoreTPL                          = 0x20
	AllocatePages                       = 0x28
	FreePages                           = 0x30
	GetMemoryMap                        = 0x38
	AllocatePool                        = 0x40
	FreePool                            = 0x48
	CreateEvent                         = 0x50
	SetTimer                            = 0x58
	WaitForEvent                        = 0x60
	SignalEvent                         = 0x68
	CloseEvent                          = 0x70
	CheckEvent                          = 0x78
	InstallProtocolInterface            = 0x80
	ReinstallProtocolInterface          = 0x88
	UninstallProtocolInterface          = 0x90
	HandleProtocol                      = 0x98
	PCHandleProtocol                    = 0xa0
	RegisterProtocolNotify              = 0xa8
	LocateHandle                        = 0xb0
	LocateDevicePath                    = 0xb8
	InstallConfigurationTable           = 0xc0
	LoadImage                           = 0xc8
	StartImage                          = 0xd0
	Exit                                = 0xd8
	UnloadImage                         = 0xe0
	ExitBootServices                    = 0xe8
	GetNextMonotonicCount               = 0xf0
	Stall                               = 0xf8
	SetWatchdogTimer                    = 0x100
	ConnectController                   = 0x108
	DisconnectController                = 0x110
	OpenProtocol                        = 0x118
	CloseProtocol                       = 0x120
	OpenProtocolInformation             = 0x128
	ProtocolsPerHandle                  = 0x130
	LocateHandleBuffer                  = 0x138
	LocateProtocol                      = 0x140
	InstallMultipleProtocolInterfaces   = 0x148
	UninstallMultipleProtocolInterfaces = 0x150
	CalculateCrc32                      = 0x158
	CopyMem                             = 0x160
	SetMem                              = 0x168
	CreateEventEx                       = 0x170
)

// BootServicesNames maps an int to a name
var BootServicesNames = map[int]string{
	RaiseTPL:                            "RaiseTPL ",
	RestoreTPL:                          "RestoreTPL ",
	AllocatePages:                       "AllocatePages ",
	FreePages:                           "FreePages ",
	GetMemoryMap:                        "GetMemoryMap ",
	AllocatePool:                        "AllocatePool ",
	FreePool:                            "FreePool ",
	CreateEvent:                         "CreateEvent ",
	SetTimer:                            "SetTimer ",
	WaitForEvent:                        "WaitForEvent ",
	SignalEvent:                         "SignalEvent ",
	CloseEvent:                          "CloseEvent ",
	CheckEvent:                          "CheckEvent ",
	InstallProtocolInterface:            "InstallProtocolInterface ",
	ReinstallProtocolInterface:          "ReinstallProtocolInterface ",
	UninstallProtocolInterface:          "UninstallProtocolInterface ",
	HandleProtocol:                      "HandleProtocol ",
	PCHandleProtocol:                    "PCHandleProtocol ",
	RegisterProtocolNotify:              "RegisterProtocolNotify ",
	LocateHandle:                        "LocateHandle ",
	LocateDevicePath:                    "LocateDevicePath ",
	InstallConfigurationTable:           "InstallConfigurationTable ",
	LoadImage:                           "LoadImage ",
	StartImage:                          "StartImage ",
	Exit:                                "Exit ",
	UnloadImage:                         "UnloadImage ",
	ExitBootServices:                    "ExitBootServices ",
	GetNextMonotonicCount:               "GetNextMonotonicCount ",
	Stall:                               "Stall ",
	SetWatchdogTimer:                    "SetWatchdogTimer ",
	ConnectController:                   "ConnectController ",
	DisconnectController:                "DisconnectController ",
	OpenProtocol:                        "OpenProtocol ",
	CloseProtocol:                       "CloseProtocol ",
	OpenProtocolInformation:             "OpenProtocolInformation ",
	ProtocolsPerHandle:                  "ProtocolsPerHandle ",
	LocateHandleBuffer:                  "LocateHandleBuffer ",
	LocateProtocol:                      "LocateProtocol ",
	InstallMultipleProtocolInterfaces:   "InstallMultipleProtocolInterfaces ",
	UninstallMultipleProtocolInterfaces: "UninstallMultipleProtocolInterfaces ",
	CalculateCrc32:                      "CalculateCrc32 ",
	CopyMem:                             "CopyMem ",
	SetMem:                              "SetMem ",
	CreateEventEx:                       "CreateEventEx ",
}
