package services

// The "BIOS" code is stored in the top 16M of the image.
// There is a "table" that represents that memory.
// ServPtrs 32-bit physical addresses, and hence must be manipulated
// to correctly access this "bios"
// TODO:
// the name tab, used everywhere, really should be BIOS
// It should be an interface.
// It probably ought to implement io.ReadWriter, so that we COULD
// just use 32-bit addresses.
// We had no idea where we were headed when we started this work.
// SetAllocator sets the base and limit of the bump-allocated data area.

// index converts 32-bit addresses to a BIOS index.
func index(p ServPtr) uint32 {
	return uint32(p) & 0xffffff
}

// ptr converts an index into a 32-bit pointer
func ptr(x uint32) uint32 {
	return x | 0xff000000
}
