package services

var (
	dat uintptr
)

// SetAllocator sets the base and limit of the bump-allocated data area.
func SetAllocator(b, lim uintptr) {
	dat = b
}

// Allocate bump allocates from the data area.
func Allocate(amt int) uintptr {
	ret := dat
	dat += uintptr(amt)
	return ret
}
