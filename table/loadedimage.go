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
	LIRevision:        &val{N: "Revision"},
	LIParentHandle:    &val{N: "ParentHandle"},
	LISystemTable:     &val{N: "SystemTable"},
	LIDeviceHandle:    &val{N: "DeviceHandle"},
	LIFilePath:        &val{N: "FilePath"},
	LIReserved:        &val{N: "Reserved"},
	LILoadOptionsSize: &val{N: "LoadOptionsSize"},
	LILoadOptions:     &val{N: "LoadOptions"},
	LIImageBase:       &val{N: "ImageBase"},
	LIImageSize:       &val{N: "ImageSize"},
	LIImageCodeType:   &val{N: "ImageCodeType"},
	LIImageDataType:   &val{N: "ImageDataType"},
	LIUnload:          &val{N: "Unload"},
}
