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

// KVMIO is for the KVMIO ioctl.
const KVMIO = 0xAE

func iIOWR(nr, size uintptr) int {
	return iIOC(readwrite, nr, size)
}
func iIOR(nr, size uintptr) int {
	return iIOC(read, nr, size)
}
func iIOW(nr, size uintptr) int {
	return iIOC(write, nr, size)
}
func iIOC(dir, nr, size uintptr) int {
	return int((dir << dirshift) | (KVMIO << typeshift) | (nr << nrshift) | (size << sizeshift))
}

var (
	setGuestDebug = iIOW(0x9b, unsafe.Sizeof(DebugControl{}))
)
