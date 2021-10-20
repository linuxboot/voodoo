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

	// don't use this	setMem        = iIOW(0x40, unsafe.Sizeof(Region{}))
	setMem = iIOW(0x46, unsafe.Sizeof(UserRegion{}))

	// shared region. No choice but to have this. Damn.
	vcpuMmapSize = iIO(0x04)

	// TODO: properly check caps. OTOH, if this is not available, what
	// will we do?
	// Available with KVM_CAP_ONE_REG
	getOneReg = iIOW(0xab, unsafe.Sizeof(OneRegister{}))
	setOneReg = iIOW(0xac, unsafe.Sizeof(OneRegister{}))
)
