package kvm

import "unsafe"

// KVMIO is for the KVMIO ioctl.
const KVMIO = 0xAE

var (
	kvmversion     = iIO(0)
	vmcreate       = iIO(1)
	checkExtension = iIO(3)
	createCPU      = iIO(0x41)
	run            = iIO(0x80)
	setGuestDebug  = iIOW(0x9b, unsafe.Sizeof(DebugControl{}))

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

var (
	// ARM specific?
	iVCPUInit = iIOW(0xae, unsafe.Sizeof(VCPUInit{}))
)

const (
	AEM          = 0
	Foundation   = 1
	Cortex57     = 2
	XgenePotenza = 3
	CortexA53    = 4
	GenericV8    = 5
)

var cpuTypes = map[int]string{
	0: "KVM_ARM_TARGET_AEM_V8",
	1: "KVM_ARM_TARGET_FOUNDATION_V8",
	2: "KVM_ARM_TARGET_CORTEX_A57",
	3: "KVM_ARM_TARGET_XGENE_POTENZA",
	4: "KVM_ARM_TARGET_CORTEX_A53",
	// Generic ARM v8 target
	5: "KVM_ARM_TARGET_GENERIC_V8",
}

var (
	iPreferredTarget = iIOR(0xaf, unsafe.Sizeof(VCPUInit{}))
)

const (
	regARM64          = 0x6000000000000000
	regu64            = 0x0030000000000000
	regARMCoprocMask  = 0x000000000FFF0000
	regARMCoprocShift = 16
	// Normal registers are mapped as coprocessor 16.
	regARMCore = (0x0010 << regARMCoprocShift)
)

// Pstate stuff
const (
	PSRModeEL1h = 0x00000005
	PSRModeEL1t = 0x00000004
	PSRModeEL0t = 0x00000000
	PSRFBit     = 0x00000040
	PSRIBit     = 0x00000080
	PSRInit     = PSRModeEL1t | PSRFBit | PSRIBit
)

// This is kinda bullshit.
// #define KVM_REG_ARM_CORE_REG(name)	(offsetof(struct kvm_regs, name) / sizeof(__u32))
// But it seems they want it, sigh.
// so what we do. Just define constants and go with it. They're never going to change
// ptrace anyway. Can't.
// struct kvm_regs {
// 	struct user_pt_regs regs;	/* sp = sp_el0 */

// 	__u64	sp_el1;
// 	__u64	elr_el1;

// 	__u64	spsr[KVM_NR_SPSR];

// 	struct user_fpsimd_state fp_regs;
// };
// struct user_pt_regs {
// 	__u64		regs[31];
// 	__u64		sp;
// 	__u64		pc;
// 	__u64		pstate;
// };
const (
	Sp      = 31
	Pc      = 32
	Pstate  = 33
	SpEL1   = 34
	ELREL   = 30
	SPSR    = 36
	NumRegs = 37
)

func coreReg(x int) uint64 {
	return regARM64 | regu64 | regARMCore | uint64(x)
}

// From Linux:
/*
 * See v8 ARM ARM D7.3: Debug Registers
 *
 * The architectural limit is 16 debug registers of each type although
 * in practice there are usually less (see ID_AA64DFR0_EL1).
 *
 * Although the control registers are architecturally defined as 32
 * bits wide we use a 64 bit structure here to keep parity with
 * KVM_GET/SET_ONE_REG behaviour which treats all system registers as
 * 64 bit values. It also allows for the possibility of the
 * architecture expanding the control registers without having to
 * change the userspace ABI.
 */

// DebugControl indicates debug info to the kernel.
type DebugControl struct {
	Control uint32
	_       uint32
	BCR     [16]uint64
	BVR     [16]uint64
	WCR     [16]uint64
	WVR     [16]uint64
}
