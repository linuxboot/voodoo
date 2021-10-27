package kvm

import "unsafe"

// KVMIO is for the KVMIO ioctl.
const KVMIO = 0xAE

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

	// The real size of the struct is determined by the first 4 bytes of it.
	// It has to be 8 bytes. Don't ask.
	setCPUID = uintptr(0x4008ae90) // iIOW(0x90, 8)
	getCPUID = iIOWR(0x05, 8)
	// don't use this	setMem        = iIOW(0x40, unsafe.Sizeof(Region{}))
	setMem = iIOW(0x46, unsafe.Sizeof(UserRegion{}))

	// shared region. No choice but to have this. Damn.
	vcpuMmapSize = iIO(0x04)

	// amd64
	setTSSAddr = iIO(0x47)
)

// DebugControl controls guest debug.
// varies with architecture. barf.
type DebugControl struct {
	Control  uint32
	_        uint32
	debugreg [8]uint64
}
