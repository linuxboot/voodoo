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

type TableMarshaler interface {
	Marshal() ([]byte, error)
}
