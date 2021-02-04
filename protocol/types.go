package protocol

// More random constants for binary structs. It's all so 1980!
const (
	LoadedImageRevision = 0x1000
)

// Basic EFI types. Suckage is really high.
type (
	// Handle is a UEFI handle, whatever that is
	Handle uintptr
	// Table is a UEFI table, ...
	Table uintptr
	// MemoryType is defined somewhere
	MemoryType uint32
	// Path is probably some pointer to what seemed a good character format in 1995
	Path uintptr
)

// LoadedImage is for the Loaded Image Protocol.
type LoadedImage struct {
	Revision uint32
	Parent   Handle
	System   Table

	//
	// Source location of image
	//
	Device   Handle
	FilePath uintptr
	_        uintptr

	//
	// Images load options
	//
	LoadOptionsSize uint32
	LoadOptions     uintptr

	//
	// Location of where image was loaded
	//
	ImageBase     uintptr
	ImageSize     uint64
	ImageCodeType MemoryType
	ImageDataType MemoryType

	//
	// If the driver image supports a dynamic unload request
	//
	/*EFI_IMAGE_UNLOAD*/
	Unload uintptr
}
