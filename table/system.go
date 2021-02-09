package table

var SystemSig = []byte{0x54, 0x53, 0x59, 0x53, 0x20, 0x49, 0x42, 0x49}

//#define EFI_SYSTEM_TABLE_REVISION      (EFI_SPECIFICATION_MAJOR_REVISION<<16) | (EFI_SPECIFICATION_MINOR_REVISION)

type SystemTable struct {
	TableHeader

	Vendor           uint16
	Revision         uint32
	FirmwareVendor   uintptr
	FirmwareRevision uint32

	ConsoleInHandle uintptr
	ConIn           uintptr

	ConsoleOutHandle uintptr
	ConOut           uintptr

	StandardErrorHandle uintptr
	StdErr              uintptr

	RuntimeServices uintptr
	BootServices    uintptr

	NumberOfTableEntries uintptr
	ConfigurationTable   uintptr
}
