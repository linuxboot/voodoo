package kvm

import "unsafe"

const (
	nrbits   = 8
	typebits = 8
	sizebits = 14
	dirbits  = 2

	none      = 0
	write     = 1
	read      = 2
	readwrite = 3

	nrshift   = 0
	typeshift = nrshift + nrbits
	sizeshift = typeshift + typebits
	dirshift  = sizeshift + sizebits
)

func iIOWR(nr, size uintptr) uintptr {
	return iIOC(readwrite, nr, size)
}
func iIOR(nr, size uintptr) uintptr {
	return iIOC(read, nr, size)
}
func iIOW(nr, size uintptr) uintptr {
	return iIOC(write, nr, size)
}
func iIO(nr uintptr) uintptr {
	return iIOC(none, nr, 0)
}
func iIOC(dir, nr, size uintptr) uintptr {
	return uintptr((dir << dirshift) | (KVMIO << typeshift) | (nr << nrshift) | (size << sizeshift))
}
