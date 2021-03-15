package kvm

import (
	"errors"
	"fmt"
	"syscall"
)

// Exit is the VM exit value returned by KVM.
type Exit uint64
type cpu struct {
	id int
}

// APIVersion is the KVM API version.
// The only API version we support.
// The only API version anyway. This was
// a mistake remedied by the capability stuff.
const APIVersion = 12

type regs struct {
	rax, rbx, rcx, rdx uint64
	rsi, rdi, rsp, rbp uint64
	r8, r9, r10, r11   uint64
	r12, r13, r14, r15 uint64
	rip, rflags        uint64
}

type segment struct {
	base                           uint64
	limit                          uint32
	selector                       uint16
	stype                          uint8
	present, dpl, db, s, l, g, avl uint8
	_                              uint8
	_                              uint8
}

type dtable struct {
	base  uint64
	limit uint16
	_     [3]uint16
}

/* for KVM_GET_SREGS and KVM_SET_SREGS */
type sregs struct {
	/* out (KVM_GET_SREGS) / in (KVM_SET_SREGS) */
	cs, ds, es, fs, gs, ss  segment
	tr, ldt                 segment
	gdt, idt                dtable
	cr0, cr2, cr3, cr4, cr8 uint64
	efer                    uint64
	apic                    uint16
	interruptBitmap         [(256 + 63) / 64]uint64
}

func kvmRegstoPtraceRegs(pr *syscall.PtraceRegs, r *regs, s *sregs) {
	pr.R15 = r.r15
	pr.R14 = r.r14
	pr.R13 = r.r13
	pr.R12 = r.r12
	pr.Rbp = r.rbp
	pr.Rbx = r.rbx
	pr.R11 = r.r11
	pr.R10 = r.r10
	pr.R9 = r.r9
	pr.R8 = r.r8
	pr.Rax = r.rax
	pr.Rcx = r.rcx
	pr.Rdx = r.rdx
	pr.Rsi = r.rsi
	pr.Rdi = r.rdi
	pr.Orig_rax = r.rax /// hmmm ....
	pr.Rip = r.rip
	//pr.Cs = r.Cs
	pr.Eflags = r.rflags
	pr.Rsp = r.rsp
	// pr.Ss = r.Ss
	// pr.Fs_base = r.Fs_base
	// pr.Gs_base = r.Gs_base
	// pr.Ds = r.Ds
	// pr.Es = r.Es
	// pr.Fs = r.Fs
	// pr.Gs = r.Gs
}

// MemoryRegion is used for CREATE_MEMORY_REGION
type MemoryRegion struct {
	slot  uint32
	flags uint32
	gpa   uint64
	size  uint64 /* bytes */
}

// CreateRegion is used for KVM_CREATE_MEMORY_REGION
type CreateRegion struct {
	slot  uint32
	flags uint32
	gpa   uint64
	size  uint64
}

// UserRegion is used for  SET_USER_MEMORY_REGION
type UserRegion struct {
	slot     uint32
	flags    uint32
	gpa      uint64
	size     uint64
	useraddr uint64
}

/*
 * The bit 0 ~ bit 15 of kvm_memory_region::flags are visible for userspace,
 * other bits are reserved for kvm internal use which are defined in
 * include/linux/kvm_host.h.
 */
//#define MEM_LOG_DIRTY_PAGES	(1UL << 0)
//#define MEM_READONLY	(1UL << 1)

// KVM exit values.
const (
	ExitUnknown       = 0
	ExitException     = 1
	ExitIo            = 2
	ExitHypercall     = 3
	ExitDebug         = 4
	ExitHlt           = 5
	ExitMmio          = 6
	ExitIrqWindowOpen = 7
	ExitShutdown      = 8
	ExitFailEntry     = 9
	ExitIntr          = 10
	ExitSetTPR        = 11
	ExitTPRAccess     = 12
	ExitNmi           = 16
	ExitInternalError = 17
	ExitOsi           = 18
	// 	ExitPapr_hcall      = 19
	ExitWatchdog    = 21
	ExitEpr         = 23
	ExitSystemEvent = 24
	ExitIoapicEOI   = 26
)

/* For ExitINTERNAL_ERROR */
/* Emulate instruction failed. */
//#define INTERNAL_ERROR_EMULATION	1
/* Encounter unexpected simultaneous exceptions. */
//#define INTERNAL_ERROR_SIMUL_EX	2
/* Encounter unexpected vm-exit due to delivery event. */
//#define INTERNAL_ERROR_DELIVERY_EV	3
/* Encounter unexpected vm-exit reason */
//#define INTERNAL_ERROR_UNEXPECTED_ExitREASON	4

// Run controls running, and is returned by mmap(vcpu_fd, offset=0)
type Run struct {
	/* in */
	RequestInterruptWindow uint8
	ImmediateExit          uint8
	_                      [6]uint8

	/* out */
	ExitReason                 uint32
	ReadyForInterruptInjection uint8
	IFFlag                     uint8
	flags                      uint16

	/* in (pre_kvm_run), out (post_kvm_run) */
	cr8      uint64
	APICBase uint64
	//////
	//////	union {
	//////		/* ExitUNKNOWN */
	//////		struct {
	//////			hardware_exit_reason uint64
	//////		} hw
	//////		/* ExitFAIL_ENTRY */
	//////		struct {
	//////			hardware_entry_failure_reason uint64
	//////		} fail_entry
	//////		/* ExitEXCEPTION */
	//////		struct {
	//////			exception uint32
	//////			error_code uint32
	//////		} ex
	//////		/* ExitIO */
	//////		struct {
	////////#define ExitIO_IN  0
	////////#define ExitIO_OUT 1
	//////			direction uint8
	//////			size uint8 /* bytes */
	//////			port uint16
	//////			count uint32
	//////			data_offset uint64 /* relative to kvm_run start */
	//////		} io
	//////		/* ExitDEBUG */
	//////		struct {
	//////			struct kvm_debug_exit_arch arch
	//////		} debug
	//////		/* ExitMMIO */
	//////		struct {
	//////			phys_addr uint64
	//////			data[8] uint8
	//////			len uint32
	//////			is_write uint8
	//////		} mmio
	//////		/* ExitHYPERCALL */
	//////		struct {
	//////			nr uint64
	//////			args[6] uint64
	//////			ret uint64
	//////			longmode uint32
	//////			pad uint32
	//////		} hypercall
	//////		/* ExitTPR_ACCESS */
	//////		struct {
	//////			rip uint64
	//////			is_write uint32
	//////			pad uint32
	//////		} tpr_access
	//////		/* ExitS390_SIEIC */
	//////		struct {
	//////			icptcode uint8
	//////			ipa uint16
	//////			ipb uint32
	//////		} s390_sieic
	//////		/* ExitINTERNAL_ERROR */
	//////		struct {
	//////			suberror uint32
	//////			/* Available with CAP_INTERNAL_ERROR_DATA: */
	//////			ndata uint32
	//////			data[16] uint64
	//////		} internal
	//////		/* ExitOSI */
	//////		struct {
	//////			gprs[32] uint64
	//////		} osi
	//////		/* ExitPAPR_HCALL */
	//////		struct {
	//////			nr uint64
	//////			ret uint64
	//////			args[9] uint64
	//////		} papr_hcall
	//////		/* ExitEPR */
	//////		struct {
	//////			epr uint32
	//////		} epr
	//////		/* ExitSYSTEM_EVENT */
	//////		struct {
	////////#define SYSTEM_EVENT_SHUTDOWN       1
	////////#define SYSTEM_EVENT_RESET          2
	////////#define SYSTEM_EVENT_CRASH          3
	//////			type uint32
	//////			flags uint64
	//////		} system_event
	//////		/* Fix the size of the union. */
	//////		char padding[256]
	//////	}
	//////
	//////	/* 2048 is the size of the char array used to bound/pad the size
	//////	 * of the union that holds sync regs.
	//////	 */
	//////	#define SYNC_REGS_SIZE_BYTES 2048
	//////	/*
	//////	 * shared registers between kvm and userspace.
	//////	 * kvm_valid_regs specifies the register classes set by the host
	//////	 * kvm_dirty_regs specified the register classes dirtied by userspace
	//////	 * struct kvm_sync_regs is architecture specific, as well as the
	//////	 * bits for kvm_valid_regs and kvm_dirty_regs
	//////	 */
	//////	kvm_valid_regs uint64
	//////	kvm_dirty_regs uint64
	//////	union {
	//////		struct kvm_sync_regs regs
	//////		char padding[SYNC_REGS_SIZE_BYTES]
	//////	} s
}

// Translate translates guest linear to physical? This is for for TRANSLATE
type Translate struct {
	// LinearAddress is input.
	LinearAddress uint64

	// This is output
	PhysicalAddress uint64
	Valid           uint8
	Writeable       uint8
	Usermode        uint8
	_               [5]uint8
}

// DirtyLog gets a log of dirty pages.
type DirtyLog struct {
	Slot uint32
	_    uint32

	//	union {
	//		void *dirty_bitmap /* one bit per page
	//		padding2 uint64
	//}

}

// ClearDirtyLog clears the dirty page log.
type ClearDirtyLog struct {
	Slot      uint32
	NumPages  uint32
	FirstPage uint64
	//	union {
	//		void *dirty_bitmap /* one bit per page */
	//		padding2 uint64
	//	}
}

// SetSignalMask sets the signal mask
type SetSignalMask struct {
	len    uint32
	sigset [0]uint8
}

// TPRAccessCtl controls how TPRAccess is reported.
type TPRAccessCtl struct {
	Enabled uint32
	Flags   uint32
	_       [8]uint32
}

// VAPICAddr sets the VAPIC address.
type VAPICAddr struct {
	Addr uint64
}

const (
	// Enable enables debug options in the guest
	Enable = 1
	// SingleStep enables single step.
	SingleStep = 2
)

// DebugControl controls guest debug.
type DebugControl struct {
	control uint32
	_       uint32
	//	arch    kvm_guest_debug_arch
}

const (
	ioeventfdFlagNRdatamatch = 0
	ioeventfdFlagNRpio
	ioeventfdFlagNRdeassign
	ioeventfdFlagNRvirtioCCWNotify
	ioeventfdFlagNRfastMMIO
	ioeventfdFlagNRmax
)

//#define IOEVENTFD_FLAG_DATAMATCH (1 << kvm_ioeventfd_flag_nr_datamatch)
//#define IOEVENTFD_FLAG_PIO       (1 << kvm_ioeventfd_flag_nr_pio)
//#define IOEVENTFD_FLAG_DEASSIGN  (1 << kvm_ioeventfd_flag_nr_deassign)
//#define IOEVENTFD_FLAG_VIRTIO_CCW_NOTIFY \
//	(1 << kvm_ioeventfd_flag_nr_virtio_ccw_notify)

//#define IOEVENTFD_VALID_FLAG_MASK  ((1 << kvm_ioeventfd_flag_nr_max) - 1)

// IOEventFD controls how events are managed.
type IOEventFD struct {
	Datamatch uint64
	Addr      uint64 /* legal pio/mmio address */
	Len       uint32 /* 1, 2, 4, or 8 or 0 to ignore length */
	FD        int32
	Flags     uint32
	_         [36]uint8
}

//#define X86_DISABLE_EXITS_MWAIT          (1 << 0)
//#define X86_DISABLE_EXITS_HLT            (1 << 1)
//#define X86_DISABLE_EXITS_PAUSE          (1 << 2)
//#define X86_DISABLE_EXITS_CSTATE         (1 << 3)
//#define X86_DISABLE_VALID_EXITS          (X86_DISABLE_EXITS_MWAIT | \
//X86_DISABLE_EXITS_HLT | \
//                                              X86_DISABLE_EXITS_PAUSE | \
//                                              X86_DISABLE_EXITS_CSTATE)

// EnableCap enables capabilities
type enableCap struct {
	/* in */
	cap   uint32
	flags uint32
	args  [4]uint64
	pad   [64]uint8
}

/*
 * Check if a kvm extension is available.  Argument is extension number,
 * return is 1 (yes) or 0 (no, sorry).
 */
//#define CHECK_EXTENSION       _IO(KVMIO,   0x03)
/*
 * Get size for mmap(vcpu_fd)
 */
//#define GET_VCPU_MMAP_SIZE    _IO(KVMIO,   0x04) /* in bytes */
//#define GET_SUPPORTED_CPUID   _IOWR(KVMIO, 0x05, struct kvm_cpuid2)
//#define GET_EMULATED_CPUID	  _IOWR(KVMIO, 0x09, struct kvm_cpuid2)
//#define GET_MSR_FEATURE_INDEX_LIST    _IOWR(KVMIO, 0x0a, struct kvm_msr_list)

/*
 * Extension capability list.
 */
//#define CAP_IRQCHIP	  0
//#define CAP_HLT	  1
//#define CAP_MMU_SHADOW_CACHE_CONTROL 2
//#define CAP_USER_MEMORY 3
//#define CAP_SET_TSS_ADDR 4
//#define CAP_VAPIC 6
//#define CAP_EXT_CPUID 7
//#define CAP_CLOCKSOURCE 8
//#define CAP_NR_VCPUS 9       /* returns recommended max vcpus per vm */
//#define CAP_NR_MEMSLOTS 10   /* returns max memory slots per vm */
//#define CAP_PIT 11
//#define CAP_NOP_IO_DELAY 12
//#define CAP_PV_MMU 13
//#define CAP_MP_STATE 14
//#define CAP_COALESCED_MMIO 15
//#define CAP_SYNC_MMU 16  /* Changes to host mmap are reflected in guest */
//#define CAP_IOMMU 18
/* Bug in SET_USER_MEMORY_REGION fixed: */
//#define CAP_DESTROY_MEMORY_REGION_WORKS 21
//#define CAP_USER_NMI 22
////#ifdef __HAVE_GUEST_DEBUG
//#define CAP_SET_GUEST_DEBUG 23
////#endif
////#ifdef __HAVE_PIT
//#define CAP_REINJECT_CONTROL 24
////#endif
//#define CAP_IRQ_ROUTING 25
//#define CAP_IRQ_INJECT_STATUS 26
//#define CAP_ASSIGN_DEV_IRQ 29
/* Another bug in SET_USER_MEMORY_REGION fixed: */
//#define CAP_JOIN_MEMORY_REGIONS_WORKS 30
////#ifdef __HAVE_MCE
//#define CAP_MCE 31
////#endif
//#define CAP_IRQFD 32
////#ifdef __HAVE_PIT
//#define CAP_PIT2 33
////#endif
//#define CAP_SET_BOOT_CPU_ID 34
////#ifdef __HAVE_PIT_STATE2
//#define CAP_PIT_STATE2 35
////#endif
//#define CAP_IOEVENTFD 36
//#define CAP_SET_IDENTITY_MAP_ADDR 37
////#ifdef __HAVE_XEN_HVM
//#define CAP_XEN_HVM 38
////#endif
//#define CAP_ADJUST_CLOCK 39
//#define CAP_INTERNAL_ERROR_DATA 40
////#ifdef __HAVE_VCPU_EVENTS
//#define CAP_VCPU_EVENTS 41
////#endif
//#define CAP_S390_PSW 42
//#define CAP_PPC_SEGSTATE 43
//#define CAP_HYPERV 44
//#define CAP_HYPERV_VAPIC 45
//#define CAP_HYPERV_SPIN 46
//#define CAP_PCI_SEGMENT 47
//#define CAP_PPC_PAIRED_SINGLES 48
//#define CAP_INTR_SHADOW 49
////#ifdef __HAVE_DEBUGREGS
//#define CAP_DEBUGREGS 50
////#endif
//#define CAP_X86_ROBUST_SINGLESTEP 51
//#define CAP_PPC_OSI 52
//#define CAP_PPC_UNSET_IRQ 53
//#define CAP_ENABLE_CAP 54
////#ifdef __HAVE_XSAVE
//#define CAP_XSAVE 55
////#endif
////#ifdef __HAVE_XCRS
//#define CAP_XCRS 56
////#endif
//#define CAP_PPC_GET_PVINFO 57
//#define CAP_PPC_IRQ_LEVEL 58
//#define CAP_ASYNC_PF 59
//#define CAP_TSC_CONTROL 60
//#define CAP_GET_TSC_KHZ 61
//#define CAP_PPC_BOOKE_SREGS 62
//#define CAP_SPAPR_TCE 63
//#define CAP_PPC_SMT 64
//#define CAP_PPC_RMA	65
//#define CAP_MAX_VCPUS 66       /* returns max vcpus per vm */
//#define CAP_PPC_HIOR 67
//#define CAP_PPC_PAPR 68
//#define CAP_SW_TLB 69
//#define CAP_ONE_REG 70
//#define CAP_S390_GMAP 71
//#define CAP_TSC_DEADLINE_TIMER 72
//#define CAP_S390_UCONTROL 73
//#define CAP_SYNC_REGS 74
//#define CAP_PCI_2_3 75
//#define CAP_KVMCLOCK_CTRL 76
//#define CAP_SIGNAL_MSI 77
//#define CAP_PPC_GET_SMMU_INFO 78
//#define CAP_S390_COW 79
//#define CAP_PPC_ALLOC_HTAB 80
//#define CAP_READONLY_MEM 81
//#define CAP_IRQFD_RESAMPLE 82
//#define CAP_PPC_BOOKE_WATCHDOG 83
//#define CAP_PPC_HTAB_FD 84
//#define CAP_S390_CSS_SUPPORT 85
//#define CAP_PPC_EPR 86
//#define CAP_ARM_PSCI 87
//#define CAP_ARM_SET_DEVICE_ADDR 88
//#define CAP_DEVICE_CTRL 89
//#define CAP_IRQ_MPIC 90
//#define CAP_PPC_RTAS 91
//#define CAP_IRQ_XICS 92
//#define CAP_ARM_EL1_32BIT 93
//#define CAP_SPAPR_MULTITCE 94
//#define CAP_EXT_EMUL_CPUID 95
//#define CAP_HYPERV_TIME 96
//#define CAP_IOAPIC_POLARITY_IGNORED 97
//#define CAP_ENABLE_CAP_VM 98
//#define CAP_S390_IRQCHIP 99
//#define CAP_IOEVENTFD_NO_LENGTH 100
//#define CAP_VM_ATTRIBUTES 101
//#define CAP_ARM_PSCI_0_2 102
//#define CAP_PPC_FIXUP_HCALL 103
//#define CAP_PPC_ENABLE_HCALL 104
//#define CAP_CHECK_EXTENSION_VM 105
//#define CAP_S390_USER_SIGP 106
//#define CAP_S390_VECTOR_REGISTERS 107
//#define CAP_S390_MEM_OP 108
//#define CAP_S390_USER_STSI 109
//#define CAP_S390_SKEYS 110
//#define CAP_MIPS_FPU 111
//#define CAP_MIPS_MSA 112
//#define CAP_S390_INJECT_IRQ 113
//#define CAP_S390_IRQ_STATE 114
//#define CAP_PPC_HWRNG 115
//#define CAP_DISABLE_QUIRKS 116
//#define CAP_X86_SMM 117
//#define CAP_MULTI_ADDRESS_SPACE 118
//#define CAP_GUEST_DEBUG_HW_BPS 119
//#define CAP_GUEST_DEBUG_HW_WPS 120
//#define CAP_SPLIT_IRQCHIP 121
//#define CAP_IOEVENTFD_ANY_LENGTH 122
//#define CAP_HYPERV_SYNIC 123
//#define CAP_S390_RI 124
//#define CAP_SPAPR_TCE_64 125
//#define CAP_ARM_PMU_V3 126
//#define CAP_VCPU_ATTRIBUTES 127
//#define CAP_MAX_VCPU_ID 128
//#define CAP_X2APIC_API 129
//#define CAP_S390_USER_INSTR0 130
//#define CAP_MSI_DEVID 131
//#define CAP_PPC_HTM 132
//#define CAP_SPAPR_RESIZE_HPT 133
//#define CAP_PPC_MMU_RADIX 134
//#define CAP_PPC_MMU_HASH_V3 135
//#define CAP_IMMEDIATE_EXIT 136
//#define CAP_MIPS_VZ 137
//#define CAP_MIPS_TE 138
//#define CAP_MIPS_64BIT 139
//#define CAP_S390_GS 140
//#define CAP_S390_AIS 141
//#define CAP_SPAPR_TCE_VFIO 142
//#define CAP_X86_DISABLE_EXITS 143
//#define CAP_ARM_USER_IRQ 144
//#define CAP_S390_CMMA_MIGRATION 145
//#define CAP_PPC_FWNMI 146
//#define CAP_PPC_SMT_POSSIBLE 147
//#define CAP_HYPERV_SYNIC2 148
//#define CAP_HYPERV_VP_INDEX 149
//#define CAP_S390_AIS_MIGRATION 150
//#define CAP_PPC_GET_CPU_CHAR 151
//#define CAP_S390_BPB 152
//#define CAP_GET_MSR_FEATURES 153
//#define CAP_HYPERV_EVENTFD 154
//#define CAP_HYPERV_TLBFLUSH 155
//#define CAP_S390_HPAGE_1M 156
//#define CAP_NESTED_STATE 157
//#define CAP_ARM_INJECT_SERROR_ESR 158
//#define CAP_MSR_PLATFORM_INFO 159
//#define CAP_PPC_NESTED_HV 160
//#define CAP_HYPERV_SEND_IPI 161
//#define CAP_COALESCED_PIO 162
//#define CAP_HYPERV_ENLIGHTENED_VMCS 163
//#define CAP_EXCEPTION_PAYLOAD 164
//#define CAP_ARM_VM_IPA_SIZE 165
//#define CAP_MANUAL_DIRTY_LOG_PROTECT 166 /* Obsolete */
//#define CAP_HYPERV_CPUID 167
//#define CAP_MANUAL_DIRTY_LOG_PROTECT2 168
//#define CAP_PPC_IRQ_XIVE 169
//#define CAP_ARM_SVE 170
//#define CAP_ARM_PTRAUTH_ADDRESS 171
//#define CAP_ARM_PTRAUTH_GENERIC 172
//#define CAP_PMU_EVENT_FILTER 173
//#define CAP_ARM_IRQ_LINE_LAYOUT_2 174
//#define CAP_HYPERV_DIRECT_TLBFLUSH 175
//#define CAP_PPC_GUEST_DEBUG_SSTEP 176
//#define CAP_ARM_NISV_TO_USER 177
//#define CAP_ARM_INJECT_EXT_DABT 178
//#define CAP_S390_VCPU_RESETS 179
//#define CAP_S390_PROTECTED 180
//#define CAP_PPC_SECURE_GUEST 181
//#define CAP_HALT_POLL 182
//#define CAP_ASYNC_PF_INT 183

/*
 * Architecture specific registers are to be defined in arch headers and
 * ORed with the arch identifier.
 */
//#define REG_PPC		0x1000000000000000ULL
//#define REG_X86		0x2000000000000000ULL
//#define REG_IA64		0x3000000000000000ULL
//#define REG_ARM		0x4000000000000000ULL
//#define REG_S390		0x5000000000000000ULL
//#define REG_ARM64		0x6000000000000000ULL
//#define REG_MIPS		0x7000000000000000ULL
//#define REG_RISCV		0x8000000000000000ULL

//#define REG_SIZE_SHIFT	52
//#define REG_SIZE_MASK	0x00f0000000000000ULL
//#define REG_SIZE_U8		0x0000000000000000ULL
//#define REG_SIZE_U16	0x0010000000000000ULL
//#define REG_SIZE_U32	0x0020000000000000ULL
//#define REG_SIZE_U64	0x0030000000000000ULL
//#define REG_SIZE_U128	0x0040000000000000ULL
//#define REG_SIZE_U256	0x0050000000000000ULL
//#define REG_SIZE_U512	0x0060000000000000ULL
//#define REG_SIZE_U1024	0x0070000000000000ULL
//#define REG_SIZE_U2048	0x0080000000000000ULL

type regList struct {
	n   uint64 /* number of regs */
	reg [0]uint64
}

type oneReg struct {
	id   uint64
	addr uint64
}

/*
 * ioctls for VM fds
 */
//#define SET_MEMORY_REGION     _IOW(KVMIO,  0x40, struct kvm_memory_region)
/*
 * CREATE_VCPU receives as a parameter the vcpu slot, and returns
 * a vcpu fd.
 */
//#define CREATE_VCPU           _IO(KVMIO,   0x41)
//#define GET_DIRTY_LOG         _IOW(KVMIO,  0x42, struct kvm_dirty_log)
/* SET_MEMORY_ALIAS is obsolete: */
//#define SET_MEMORY_ALIAS      _IOW(KVMIO,  0x43, struct kvm_memory_alias)
//#define SET_NR_MMU_PAGES      _IO(KVMIO,   0x44)
//#define GET_NR_MMU_PAGES      _IO(KVMIO,   0x45)
//#define SET_USER_MEMORY_REGION _IOW(KVMIO, 0x46, \
//				struct kvm_userspace_memory_region)
//#define SET_TSS_ADDR          _IO(KVMIO,   0x47)
//#define SET_IDENTITY_MAP_ADDR _IOW(KVMIO,  0x48, __u64)

/*
 * ioctls for vcpu fds
 */
//#define RUN                   _IO(KVMIO,   0x80)
//#define GET_REGS              _IOR(KVMIO,  0x81, struct kvm_regs)
//#define SET_REGS              _IOW(KVMIO,  0x82, struct kvm_regs)
//#define GET_SREGS             _IOR(KVMIO,  0x83, struct kvm_sregs)
//#define SET_SREGS             _IOW(KVMIO,  0x84, struct kvm_sregs)
//#define TRANSLATE             _IOWR(KVMIO, 0x85, struct kvm_translation)
//#define INTERRUPT             _IOW(KVMIO,  0x86, struct kvm_interrupt)
/* DEBUG_GUEST is no longer supported, use SET_GUEST_DEBUG instead */
//#define DEBUG_GUEST           __DEPRECATED_VCPU_W_0x87
//#define GET_MSRS              _IOWR(KVMIO, 0x88, struct kvm_msrs)
//#define SET_MSRS              _IOW(KVMIO,  0x89, struct kvm_msrs)
//#define SET_CPUID             _IOW(KVMIO,  0x8a, struct kvm_cpuid)
//#define SET_SIGNAL_MASK       _IOW(KVMIO,  0x8b, struct kvm_signal_mask)
//#define GET_FPU               _IOR(KVMIO,  0x8c, struct kvm_fpu)
//#define SET_FPU               _IOW(KVMIO,  0x8d, struct kvm_fpu)
//#define GET_LAPIC             _IOR(KVMIO,  0x8e, struct kvm_lapic_state)
//#define SET_LAPIC             _IOW(KVMIO,  0x8f, struct kvm_lapic_state)
//#define SET_CPUID2            _IOW(KVMIO,  0x90, struct kvm_cpuid2)
//#define GET_CPUID2            _IOWR(KVMIO, 0x91, struct kvm_cpuid2)
/* Available with CAP_VAPIC */
//#define TPR_ACCESS_REPORTING  _IOWR(KVMIO, 0x92, struct kvm_tpr_access_ctl)
/* Available with CAP_VAPIC */
//#define SET_VAPIC_ADDR        _IOW(KVMIO,  0x93, struct kvm_vapic_addr)
/* Available with CAP_USER_NMI */
//#define NMI                   _IO(KVMIO,   0x9a)
/* Available with CAP_SET_GUEST_DEBUG */
//#define SET_GUEST_DEBUG       _IOW(KVMIO,  0x9b, struct kvm_guest_debug)
/* MCE for x86 */
//#define X86_SETUP_MCE         _IOW(KVMIO,  0x9c, __u64)
//#define X86_GET_MCE_CAP_SUPPORTED _IOR(KVMIO,  0x9d, __u64)
//#define X86_SET_MCE           _IOW(KVMIO,  0x9e, struct kvm_x86_mce)
/* Available with CAP_VCPU_EVENTS */
//#define GET_VCPU_EVENTS       _IOR(KVMIO,  0x9f, struct kvm_vcpu_events)
//#define SET_VCPU_EVENTS       _IOW(KVMIO,  0xa0, struct kvm_vcpu_events)
/* Available with CAP_DEBUGREGS */
//#define GET_DEBUGREGS         _IOR(KVMIO,  0xa1, struct kvm_debugregs)
//#define SET_DEBUGREGS         _IOW(KVMIO,  0xa2, struct kvm_debugregs)
/*
 * vcpu version available with ENABLE_CAP
 * vm version available with CAP_ENABLE_CAP_VM
 */
//#define ENABLE_CAP            _IOW(KVMIO,  0xa3, struct kvm_enable_cap)
/* Available with CAP_XSAVE */
//#define GET_XSAVE		  _IOR(KVMIO,  0xa4, struct kvm_xsave)
//#define SET_XSAVE		  _IOW(KVMIO,  0xa5, struct kvm_xsave)
/* Available with CAP_XCRS */
//#define GET_XCRS		  _IOR(KVMIO,  0xa6, struct kvm_xcrs)
//#define SET_XCRS		  _IOW(KVMIO,  0xa7, struct kvm_xcrs)
/* Available with CAP_SW_TLB */
//#define DIRTY_TLB		  _IOW(KVMIO,  0xaa, struct kvm_dirty_tlb)
/* Available with CAP_ONE_REG */
//#define GET_ONE_REG		  _IOW(KVMIO,  0xab, struct kvm_one_reg)
//#define SET_ONE_REG		  _IOW(KVMIO,  0xac, struct kvm_one_reg)
/* VM is being stopped by host */
//#define KVMCLOCK_CTRL	  _IO(KVMIO,   0xad)
//#define GET_REG_LIST	  _IOWR(KVMIO, 0xb0, struct kvm_reg_list)

func (e *Exit) String() string {
	switch *e {
	case ExitUnknown:
		return "ExitUnknown"
	case ExitException:
		return "ExitException"
	case ExitIo:
		return "ExitIo"
	case ExitHypercall:
		return "ExitHypercall"
	case ExitDebug:
		return "ExitDebug"
	case ExitHlt:
		return "ExitHlt"
	case ExitMmio:
		return "ExitMmio"
	case ExitIrqWindowOpen:
		return "ExitIrq_window_open"
	case ExitShutdown:
		return "ExitShutdown"
	case ExitFailEntry:
		return "ExitFail_entry"
	case ExitIntr:
		return "ExitIntr"
	case ExitSetTPR:
		return "ExitSet_tpr"
	case ExitTPRAccess:
		return "ExitTpr_access"
	case ExitNmi:
		return "ExitNmi"
	case ExitInternalError:
		return "ExitInternal_error"
	case ExitOsi:
		return "ExitOsi"
	case ExitWatchdog:
		return "ExitWatchdog"
	case ExitEpr:
		return "ExitEpr"
	case ExitSystemEvent:
		return "ExitSystem_event"
	case ExitIoapicEOI:
		return "ExitIoapic_eoi"
	}
	return fmt.Sprintf("unknown exit %#x", *e)
}

// rflags = regs.rflags;

// rip = regs.rip; rsp = regs.rsp;
// rax = regs.rax; rbx = regs.rbx; rcx = regs.rcx;
// rdx = regs.rdx; rsi = regs.rsi; rdi = regs.rdi;
// rbp = regs.rbp; r8  = regs.r8;  r9  = regs.r9;
// r10 = regs.r10; r11 = regs.r11; r12 = regs.r12;
// r13 = regs.r13; r14 = regs.r14; r15 = regs.r15;

// dprintf(debug_fd, "\n Registers:\n");
// dprintf(debug_fd,   " ----------\n");
// dprintf(debug_fd, " rip: %016lx   rsp: %016lx flags: %016lx\n", rip, rsp, rflags);
// dprintf(debug_fd, " rax: %016lx   rbx: %016lx   rcx: %016lx\n", rax, rbx, rcx);
// dprintf(debug_fd, " rdx: %016lx   rsi: %016lx   rdi: %016lx\n", rdx, rsi, rdi);
// dprintf(debug_fd, " rbp: %016lx    r8: %016lx    r9: %016lx\n", rbp, r8,  r9);
// dprintf(debug_fd, " r10: %016lx   r11: %016lx   r12: %016lx\n", r10, r11, r12);
// dprintf(debug_fd, " r13: %016lx   r14: %016lx   r15: %016lx\n", r13, r14, r15);

// if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
// 	die("KVM_GET_REGS failed");

// cr0 = sregs.cr0; cr2 = sregs.cr2; cr3 = sregs.cr3;
// cr4 = sregs.cr4; cr8 = sregs.cr8;

// GetRegs reads the registers from the inferior.
func (t *Tracee) GetRegs() (*syscall.PtraceRegs, error) {
	errchan := make(chan error, 1)
	value := make(chan *syscall.PtraceRegs, 1)
	if t.do(func() {
		pr := &syscall.PtraceRegs{}
		r := &regs{}
		s := &sregs{}
		if _, _, err := t.ioctl(getRegs, &r); err != nil {
			value <- nil
			errchan <- err
		}
		if false {
			if _, _, err := t.ioctl(getSregs, &s); err != nil {
				value <- nil
				errchan <- err
			}
		}
		kvmRegstoPtraceRegs(pr, r, s)
		value <- pr
		errchan <- nil
	}) {
		return <-value, <-errchan
	}
	return &syscall.PtraceRegs{}, errors.New("GetRegs: Unreachable")
}

// GetIPtr reads the instruction pointer from the inferior and returns it.
func (t *Tracee) GetIPtr() (uintptr, error) {
	errchan := make(chan error, 1)
	value := make(chan uintptr, 1)
	if t.do(func() {
		var regs syscall.PtraceRegs
		regs.Rip = 0
		err := syscall.PtraceGetRegs(int(t.dev.Fd()), &regs)
		value <- uintptr(regs.Rip)
		errchan <- err
	}) {
		return <-value, <-errchan
	}
	return 0, ErrTraceeExited
}

// SetIPtr sets the instruction pointer for a Tracee.
func (t *Tracee) SetIPtr(addr uintptr) error {
	errchan := make(chan error, 1)
	if t.do(func() {
		var regs syscall.PtraceRegs
		err := syscall.PtraceGetRegs(int(t.dev.Fd()), &regs)
		if err != nil {
			errchan <- err
			return
		}
		regs.Rip = uint64(addr)
		err = syscall.PtraceSetRegs(int(t.dev.Fd()), &regs)
		errchan <- err
	}) {
		return <-errchan
	}
	return ErrTraceeExited
}

// SetRegs sets regs for a Tracee.
func (t *Tracee) SetRegs(regs *syscall.PtraceRegs) error {
	errchan := make(chan error, 1)
	if t.do(func() {
		err := syscall.PtraceSetRegs(int(t.dev.Fd()), regs)
		errchan <- err
	}) {
		return <-errchan
	}
	return ErrTraceeExited
}
