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

var (
	kvmversion    = iIO(0)
	vmcreate      = iIO(1)
	createCPU     = iIO(0x41)
	run           = iIO(0x80)
	setGuestDebug = iIOW(0x9b, unsafe.Sizeof(DebugControl{}))
	getRegs       = iIOR(0x81, unsafe.Sizeof(regs{}))
	setRegs       = iIOW(0x82, unsafe.Sizeof(regs{}))
	getSregs      = iIOR(0x83, unsafe.Sizeof(sregs{}))
	setSregs      = iIOW(0x84, unsafe.Sizeof(sregs{}))
	// don't use this	setMem        = iIOW(0x40, unsafe.Sizeof(Region{}))
	setMem = iIOW(0x46, unsafe.Sizeof(UserRegion{}))
)
