package table

var SystemSig = []byte{0x54, 0x53, 0x59, 0x53, 0x20, 0x49, 0x42, 0x49}

//#define EFI_SYSTEM_TABLE_REVISION      (EFI_SPECIFICATION_MAJOR_REVISION<<16) | (EFI_SPECIFICATION_MINOR_REVISION)

type SystemTable struct {
	TableHeader

	Vendor           uint16
	Revision         uint32
	FirmwareVendor   uintptr
	FirmwareRevision uint32

	ConInHandle uintptr
	ConIn       uintptr

	ConOutHandle uintptr
	ConOut       uintptr

	StdErrHandle uintptr
	StdErr       uintptr

	RuntimeServices uintptr
	BootServices    uintptr

	NumberOfTableEntries uintptr
	ConfigurationTable   uintptr
}

const (
	Hdr                  = 0
	FirmwareVendor       = 0x18
	FirmwareRevision     = 0x20
	ConInHandle          = 0x28
	ConIn                = 0x30
	ConOutHandle         = 0x38
	ConOut               = 0x40
	StdErrHandle         = 0x48
	StdErr               = 0x50
	RuntimeServices      = 0x58
	BootServices         = 0x60
	NumberOfTableEntries = 0x68
	ConfigurationTable   = 0x70
)

type val struct {
	N   string
	Val uint64
}

// String is a stringer for val
func (v *val) String() string {
	return v.N
}

// SystemTableNames provide names and values for system table entries.
var SystemTableNames = map[uint64]*val{
	Hdr:                  {N: "Hdr"},
	FirmwareVendor:       {N: "FirmwareVendor"},
	FirmwareRevision:     {N: "FirmwareRevision"},
	ConInHandle:          {N: "ConInHandle"},
	ConIn:                {N: "ConIn"},
	ConOutHandle:         {N: "ConOutHandle"},
	ConOut:               {N: "ConOut"},
	StdErrHandle:         {N: "StdErrHandle"},
	StdErr:               {N: "StdErr"},
	RuntimeServices:      {N: "RuntimeServices"},
	BootServices:         {N: "BootServices"},
	NumberOfTableEntries: {N: "NumberOfTableEntries"},
	ConfigurationTable:   {N: "ConfigurationTable"},
}
