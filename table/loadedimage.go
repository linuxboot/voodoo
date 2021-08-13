package table

const (
	LIRevision        = 0
	LIParentHandle    = 0x8
	LISystemTable     = 0x10
	LIDeviceHandle    = 0x18
	LIFilePath        = 0x20
	LIReserved        = 0x28
	LILoadOptionsSize = 0x30
	LILoadOptions     = 0x38
	LIImageBase       = 0x40
	LIImageSize       = 0x48
	LIImageCodeType   = 0x50
	LIImageDataType   = 0x54
	LIUnload          = 0x58
)

var LoadedImageTableNames = map[uint64]*val{
	LIRevision:        {N: "Revision"},
	LIParentHandle:    {N: "ParentHandle"},
	LISystemTable:     {N: "SystemTable"},
	LIDeviceHandle:    {N: "DeviceHandle"},
	LIFilePath:        {N: "FilePath"},
	LIReserved:        {N: "Reserved"},
	LILoadOptionsSize: {N: "LoadOptionsSize"},
	LILoadOptions:     {N: "LoadOptions"},
	LIImageBase:       {N: "ImageBase"},
	LIImageSize:       {N: "ImageSize"},
	LIImageCodeType:   {N: "ImageCodeType"},
	LIImageDataType:   {N: "ImageDataType"},
	LIUnload:          {N: "Unload"},
}
