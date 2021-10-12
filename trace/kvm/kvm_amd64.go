package kvm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	/* CR0 bits */
	CR0_PE = 1
	CR0_MP = (1 << 1)
	CR0_EM = (1 << 2)
	CR0_TS = (1 << 3)
	CR0_ET = (1 << 4)
	CR0_NE = (1 << 5)
	CR0_WP = (1 << 16)
	CR0_AM = (1 << 18)
	CR0_NW = (1 << 29)
	CR0_CD = (1 << 30)
	CR0_PG = (1 << 31)

	/* CR4= bits */
	CR4_VME        = 1
	CR4_PVI        = (1 << 1)
	CR4_TSD        = (1 << 2)
	CR4_DE         = (1 << 3)
	CR4_PSE        = (1 << 4)
	CR4_PAE        = (1 << 5)
	CR4_MCE        = (1 << 6)
	CR4_PGE        = (1 << 7)
	CR4_PCE        = (1 << 8)
	CR4_OSFXSR     = (1 << 8)
	CR4_OSXMMEXCPT = (1 << 10)
	CR4_UMIP       = (1 << 11)
	CR4_VMXE       = (1 << 13)
	CR4_SMXE       = (1 << 14)
	CR4_FSGSBASE   = (1 << 16)
	CR4_PCIDE      = (1 << 17)
	CR4_OSXSAVE    = (1 << 18)
	CR4_SMEP       = (1 << 20)
	CR4_SMAP       = (1 << 21)

	EFER_SCE = 1
	EFER_LME = (1 << 8)
	EFER_LMA = (1 << 10)
	EFER_NXE = (1 << 11)

	/* 64-bit page * entry bits */
	PDE64_PRESENT  = 1
	PDE64_RW       = (1 << 1)
	PDE64_USER     = (1 << 2)
	PDE64_ACCESSED = (1 << 5)
	PDE64_DIRTY    = (1 << 6)
	PDE64_PS       = (1 << 7)
	PDE64_G        = (1 << 8)
)

// Exit= is the VM exit value returned by KVM.
type Exit uint32

type cpu struct {
	id    int
	fd    uintptr
	m     []byte
	VMRun VMRun
	// We have to read the CPUIDs from the vmfd,
	// and then set them into the vcpu
	idInfo *CPUIDInfo
}

// String implemnts String
func (c *cpu) String() string {
	return fmt.Sprintf("{id %x, fd %d}", c.id, c.fd)
}

// APIVersion is the KVM API version.
// The only API version we support.
// The only API version anyway. This was
// a mistake remedied by the capability stuff.
const APIVersion = 12

// PageTableBase is where our initial page tables go.
// EFI apps should not go near this.
const PageTableBase = 0xffff0000

//  {rax=0, rbx=0, rcx=0, rdx=0, rsi=0, rdi=0, rsp=0, rbp=0, r8=0, r9=0, r10=0, r11=0, r12=0, r13=0, r14=0, r15=0, rip=0xfff0, rflags=0x2}
type regs struct {
	Rax, Rbx, Rcx, Rdx uint64
	Rsi, Rdi, Rsp, Rbp uint64
	R8, R9, R10, R11   uint64
	R12, R13, R14, R15 uint64
	Rip, Rflags        uint64
}

type segment struct {
	Base                           uint64
	Limit                          uint32
	Selector                       uint16
	Stype                          uint8
	Present, DPL, DB, S, L, G, AVL uint8
	_                              uint8
	_                              uint8
}

// We really hoped to avoid this but ...
// This is the cpuid2 struct but there's no reason
// to adopt that naming

// CPUIDEntry is one cpuid entry returned by
// KVM.
type CPUIDEntry struct {
	function uint32
	index    uint32
	flags    uint32
	eax      uint32
	ebx      uint32
	ecx      uint32
	edx      uint32
	_        [3]uint32
}

// CPUIDInfo contains information about CPUID information.
// We've learned the hard way that it's best for the
// ents array to be really large -- too large --
// 256 seems appropriate. KVM does not provide partial
// results; it just returns an error if len(ents) is too
// small.
type CPUIDInfo struct {
	nent uint32
	_    uint32
	ents [256]CPUIDEntry
}

// String implements String. It returns a string formatted as strace formats it:
// {nent=54, entries=[{function=0, index=0, flags=0, eax=0xd, ebx=0x68747541, ecx=0x444d4163, edx=0x69746e65},
func (e *CPUIDEntry) String() string {
	return fmt.Sprintf("{function=%#x, index=%#x, flags=%#x, eax=%#x, ebx=%#x, ecx=%#x, edx=%#x}", e.function, e.index, e.flags, e.eax, e.ebx, e.ecx, e.edx)
}

// String implements String. It returns a string formatted as strace would format it:
// {nent=54, entries=[{function=0, index=0, flags=0, eax=0xd, ebx=0x68747541, ecx=0x444d4163, edx=0x69746e65}, ...
// With the one difference that there is a single line per cpuid (makes finding issues way easier)
func (i *CPUIDInfo) String() string {
	s := fmt.Sprintf("{nent=%d, entries=[", i.nent)
	// if n.ent is out of range we are in so much trouble we might
	// as well just die.
	for _, e := range i.ents[:i.nent] {
		s += "\n"
		s += e.String()
	}
	s += "\n]}"
	return s
}

type dtable struct {
	Base  uint64
	Limit uint16
	_     [3]uint16
}

/* for KVM_GET_SREGS and KVM_SET_SREGS */
type sregs struct {
	/* out (KVM_GET_SREGS) / in (KVM_SET_SREGS) */
	CS, DS, ES, FS, GS, SS  segment
	TR, LDT                 segment
	GDT, IDT                dtable
	CR0, CR2, CR3, CR4, CR8 uint64
	EFER                    uint64
	APIC                    uint64
	InterruptBitmap         [(256 + 63) / 64]uint64
}

func kvmRegstoPtraceRegs(pr *syscall.PtraceRegs, r *regs, s *sregs) {
	pr.R15 = r.R15
	pr.R14 = r.R14
	pr.R13 = r.R13
	pr.R12 = r.R12
	pr.Rbp = r.Rbp
	pr.Rbx = r.Rbx
	pr.R11 = r.R11
	pr.R10 = r.R10
	pr.R9 = r.R9
	pr.R8 = r.R8
	pr.Rax = r.Rax
	pr.Rcx = r.Rcx
	pr.Rdx = r.Rdx
	pr.Rsi = r.Rsi
	pr.Rdi = r.Rdi
	pr.Orig_rax = r.Rax /// hmmm ....
	pr.Rip = r.Rip
	pr.Cs = uint64(s.CS.Selector)
	pr.Eflags = r.Rflags
	pr.Rsp = r.Rsp
	pr.Ss = uint64(s.SS.Selector)
	//pr.Fs_base = uint64(s.fs_base.Selector)
	//pr.Gs_base = uint64(s.gs_base.Selector)
	pr.Ds = uint64(s.DS.Selector)
	pr.Es = uint64(s.ES.Selector)
	pr.Fs = uint64(s.FS.Selector)
	pr.Gs = uint64(s.GS.Selector)
}

func ptraceRegsToKVMRegs(pr *syscall.PtraceRegs, r *regs, s *sregs) {
	r.R15 = pr.R15
	r.R14 = pr.R14
	r.R13 = pr.R13
	r.R12 = pr.R12
	r.Rbp = pr.Rbp
	r.Rbx = pr.Rbx
	r.R11 = pr.R11
	r.R10 = pr.R10
	r.R9 = pr.R9
	r.R8 = pr.R8
	r.Rax = pr.Rax
	r.Rcx = pr.Rcx
	r.Rdx = pr.Rdx
	r.Rsi = pr.Rsi
	r.Rdi = pr.Rdi
	r.Rip = pr.Rip
	s.CS.Selector = uint16(pr.Cs)
	r.Rflags = pr.Eflags
	r.Rsp = pr.Rsp
	s.SS.Selector = uint16(pr.Ss)
	//s.fs_base = pr.Fs_base
	//s.gs_base = pr.Gs_base
	s.DS.Selector = uint16(pr.Ds)
	s.ES.Selector = uint16(pr.Es)
	s.FS.Selector = uint16(pr.Fs)
	s.GS.Selector = uint16(pr.Gs)
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

func (e Exit) String() string {
	switch e {
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
		return "ExitHalt"
	case ExitMmio:
		return "ExitMmio"
	case ExitIrqWindowOpen:
		return "ExitIrqWindowOpen"
	case ExitShutdown:
		return "ExitShutdown"
	case ExitFailEntry:
		return "ExitFailEntry"
	case ExitIntr:
		return "ExitIntr"
	case ExitSetTPR:
		return "ExitSetTPR"
	case ExitTPRAccess:
		return "ExitTprAccess"
	case ExitNmi:
		return "ExitNmi"
	case ExitInternalError:
		return "ExitInternalError"
	case ExitOsi:
		return "ExitOsi"
	case ExitWatchdog:
		return "ExitWatchdog"
	case ExitEpr:
		return "ExitEpr"
	case ExitSystemEvent:
		return "ExitSystemEvent"
	case ExitIoapicEOI:
		return "ExitIoapicEOI"
	}
	return fmt.Sprintf("unknown exit %#x", e)
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

// getRegs reads all the regs; it is useful for the few cases that need more information.
func (t Tracee) getRegs() (*regs, *sregs, error) {
	// This model can get kludgy.
	type all struct {
		err error
		s   *sregs
		r   *regs
	}
	var rdata [unsafe.Sizeof(regs{})]byte
	var sdata [unsafe.Sizeof(sregs{})]byte
	r := &regs{}
	s := &sregs{}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), getRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
		return nil, nil, errno
	}
	if err := binary.Read(bytes.NewReader(rdata[:]), binary.LittleEndian, r); err != nil {
		return nil, nil, err
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), getSregs, uintptr(unsafe.Pointer(&sdata[0]))); errno != 0 {
		return nil, nil, errno
	}
	if err := binary.Read(bytes.NewReader(sdata[:]), binary.LittleEndian, s); err != nil {
		return nil, nil, err
	}
	return r, s, nil
}

// GetRegs reads the registers from the inferior.
func (t *Tracee) GetRegs() (*syscall.PtraceRegs, error) {
	r, s, err := t.getRegs()
	if err != nil {
		return nil, err
	}
	pr := &syscall.PtraceRegs{}
	kvmRegstoPtraceRegs(pr, r, s)
	return pr, nil
}

// SetRegs sets regs for a Tracee.
// The ability to set sregs is limited by what can be set in ptraceregs.
func (t *Tracee) SetRegs(pr *syscall.PtraceRegs) error {
	rdata, sdata := &bytes.Buffer{}, &bytes.Buffer{}
	r := &regs{}
	s := &sregs{}
	ptraceRegsToKVMRegs(pr, r, s)
	if err := binary.Write(rdata, binary.LittleEndian, r); err != nil {
		return err
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), setRegs, uintptr(unsafe.Pointer(&rdata.Bytes()[0]))); errno != 0 {
		return errno
	}

	// We will not allow setting Sregs. It's too dangerous.
	// ptraceregs don't have enough useful bits.
	// At some point we might filter the settings and allow
	// *some* to be set but that's for later.
	if false {
		if err := binary.Write(sdata, binary.LittleEndian, s); err != nil {
			return err
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), setSregs, uintptr(unsafe.Pointer(&sdata.Bytes()[0]))); errno != 0 {
			return errno
		}
	}
	return nil
}

func tioctl(fd int, op uintptr, arg uintptr) (int, error) {
	r1, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), op, arg)
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

//func Mmap(fd int, offset int64, length int, prot int, flags int) (data []byte, err error)
//        void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
func mmap(_ uintptr, length uintptr, prot int, flags int, fd int, offset uintptr) ([]byte, error) {
	return unix.Mmap(fd, int64(offset), int(length), prot, flags)
}

func readonly(b []byte) error {
	base := uintptr(unsafe.Pointer(&b[0]))
	sz := uintptr(len(b))
	_, _, errno := syscall.Syscall6(syscall.SYS_MPROTECT, base, sz, syscall.PROT_READ, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("Marking %#x/%#x readonly: %v", base, sz, errno)
	}
	return nil
}

// We are going for broke here, setting up a 64-bit machine.
// We also set up the BIOS areas, at 0xe0000 and 0xff000000.
func (t *Tracee) archInit() error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.vm), setTSSAddr, 0xfffbd000)
	if errno != 0 {
		return errno
	}
	// This is exactly following the TestHalt failing test, if that matters to you.
	vcpufd, err := tioctl(int(t.vm), createCPU, 0)
	if err != nil {
		return err
	}

	vcpu_mmap_size, err := tioctl(int(t.dev.Fd()), vcpuMmapSize, 0)
	if err != nil {
		return err
	}

	kvm_run, err := mmap(0, uintptr(vcpu_mmap_size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, vcpufd, 0)
	if err != nil {
		return err
	}
	t.cpu.id = 0
	t.cpu.fd = uintptr(vcpufd)
	t.cpu.m = kvm_run

	var regions = []struct {
		base uintptr
		size uintptr
		dat  []byte
	}{
		{base: 0, size: 0x8000_0000},
		{base: 0xffff0000, size: 0x10000},
		{base: 0xff000000, size: 0x800000},
	}
	for i, s := range regions {
		mem, err := mmap(s.base, s.size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE, -1, 0)
		if err != nil {
			return err
		}

		for i := range mem {
			mem[i] = 0xf4
		}

		p := &bytes.Buffer{}
		u := &UserRegion{Slot: uint32(i), Flags: 0, GPA: uint64(s.base), Size: uint64(s.size), UserAddr: uint64(uintptr(unsafe.Pointer(&mem[0])))}
		if err := binary.Write(p, binary.LittleEndian, u); err != nil {
			return err
		}
		if false {
			log.Printf("ioctl %s", hex.Dump(p.Bytes()))
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.vm), uintptr(setMem), uintptr(unsafe.Pointer(&p.Bytes()[0]))); errno != 0 {
			return err
		}
		regions[i].dat = mem
		t.regions = append(t.regions, &Region{slot: uint32(i), gpa: uint64(s.base), data: mem})
	}

	// slot 0 is low memory, to 2g for now.

	// slot 1 is high bios, 64k at top of 4g.
	high64k := regions[1].dat
	// Set up page tables for long mode.
	// take the first six pages of an area it should not touch -- PageTableBase
	// present, read/write, page table at 0xffff0000
	// ptes[0] = PageTableBase + 0x1000 | 0x3
	// 3 in lowest 2 bits means present and read/write
	// 0x60 means accessed/dirty
	// 0x80 means the page size bit -- 0x80 | 0x60 = 0xe0
	// 0x10 here is making it point at the next page.
	copy(high64k[:], []byte{0x03, 0x10 | uint8((PageTableBase>>8)&0xff), uint8((PageTableBase >> 16) & 0xff), uint8((PageTableBase >> 24) & 0xff), 0, 0, 0, 0})
	// need four pointers to 2M page tables -- PHYSICAL addresses:
	// 0x2000, 0x3000, 0x4000, 0x5000
	for i := uint64(0); i < 4; i++ {
		ptb := PageTableBase + (i+2)*0x1000
		copy(high64k[int(i*8)+0x1000:], []byte{0x63, uint8((ptb >> 8) & 0xff), uint8((ptb >> 16) & 0xff), uint8((ptb >> 24) & 0xff), 0, 0, 0, 0})
	}
	// Now the 2M pages.
	for i := uint64(0); i < 0x1_0000_0000; i += 0x2_00_000 {
		ptb := i | 0xe3
		ix := int((i/0x2_00_000)*8 + 0x2000)
		copy(high64k[ix:], []byte{uint8(ptb), uint8((ptb >> 8) & 0xff), uint8((ptb >> 16) & 0xff), uint8((ptb >> 24) & 0xff), 0, 0, 0, 0})
	}
	if true {
		Debug("Page tables: %s", hex.Dump(high64k[:0x6000]))
	}
	// Set up 8M of image table data at 0xff000000
	// UEFI mixes function pointers and data in the protocol structs.
	// yegads it's so bad.
	//
	// The pattern needs to work if there is a deref via load/store
	// or via call.
	// poison it with hlt.
	if true {
		for i := 0; i < len(regions[2].dat); i += 8 {
			// bogus pointer but the low 16 bits are hlt; retq
			bogus := uint64(0x10000c3f4)
			bogus = uint64(0xc3f4) | uint64(0xdeadbe<<36) | uint64(i<<16)
			binary.LittleEndian.PutUint64(regions[2].dat[i:], bogus)
		}
		if err := readonly(regions[2].dat[0x400000:]); err != nil {
			log.Panicf("Marking ffun readonly: %v", err)
		}
	}
	t.tab = regions[2].dat
	// Now for CPUID. What a pain.
	var i = &CPUIDInfo{
		nent: uint32(len(CPUIDInfo{}.ents)),
	}
	Debug("Check CPUID entries")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.dev.Fd()), getCPUID, uintptr(unsafe.Pointer(i))); errno != 0 {
		Debug("Check CPUID entries err %v", errno)
		return fmt.Errorf("Getting CPUID entries: %v", errno)
	}
	Debug("%v", i)
	t.cpu.idInfo = i

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setCPUID, uintptr(unsafe.Pointer(i))); errno != 0 {
		return fmt.Errorf("Set  CPUID entries err %v", errno)
	}

	// We learned the hard way: for portability, you MUST read all the processor state, e.g. segment stuff,
	// modify it to taste, and write it back. You can NOT simply cons up what you think are correct values
	// and write them.
	// We're leaving the broken code here as a warning, in case someone gets tempted.
	// This worked for a long time on AMD, then failed on Intel, and this was the reason.
	if false {
		sdata := &bytes.Buffer{}
		if err := binary.Write(sdata, binary.LittleEndian, bit64); err != nil {
			return err
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), setSregs, uintptr(unsafe.Pointer(&sdata.Bytes()[0]))); errno != 0 {
			return fmt.Errorf("can not set sregs: %v", errno)
		}
	} else {
		Debug("Testing 64-bit mode\n")
		var rdata [unsafe.Sizeof(regs{})]byte
		var sdata [unsafe.Sizeof(sregs{})]byte
		r := &regs{}
		s := &sregs{}

		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), getRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
			return errno
		}
		if err := binary.Read(bytes.NewReader(rdata[:]), binary.LittleEndian, r); err != nil {
			return err
		}

		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), getSregs, uintptr(unsafe.Pointer(&sdata[0]))); errno != 0 {
			return errno
		}
		if err := binary.Read(bytes.NewReader(sdata[:]), binary.LittleEndian, s); err != nil {
			return err
		}

		s.CR3 = uint64(0xffff_0000)
		s.CR4 = CR4_PAE
		s.CR0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG
		s.EFER = EFER_LME | EFER_LMA

		seg := segment{
			Base:     0,
			Limit:    0xffffffff,
			Selector: 1 << 3,
			Present:  1,
			Stype:    11, /* Code: execute, read, accessed */
			DPL:      0,
			DB:       0,
			S:        1, /* Code/data */
			L:        1,
			G:        1, /* 4KB granularity */
			AVL:      0,
		}

		s.CS = seg

		seg.Stype = 3 /* Data: read/write, accessed */
		seg.Selector = 2 << 3
		s.DS, s.ES, s.FS, s.GS, s.SS = seg, seg, seg, seg, seg

		/* Clear all FLAGS bits, except bit 1 which is always set. */
		r.Rflags = 2
		r.Rip = 0x100000
		/* Create stack at top of 2 MB page and grow down. */
		r.Rsp = 2 << 20

		if err := binary.Write(bytes.NewBuffer(rdata[:]), binary.LittleEndian, r); err != nil {
			return err
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), setRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
			return errno
		}

		var sw = &bytes.Buffer{}
		if err := binary.Write(sw, binary.LittleEndian, s); err != nil {
			return err
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), setSregs, uintptr(unsafe.Pointer(&sw.Bytes()[0]))); errno != 0 {
			return errno
		}

	}
	return nil
}

func (t *Tracee) archNewProc() error {
	return nil
	Debug("Set CPUID entries in %v", t)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), setCPUID, uintptr(unsafe.Pointer(t.cpu.idInfo))); errno != 0 {
		Debug("Set  CPUID entries err %v", errno)
		return fmt.Errorf("Setting CPUID entries: %v", errno)
	}

	return nil
}

var bit64 = &sregs{
	CS:   segment{Base: 0, Limit: 0xffffffff, Selector: 8, Stype: 11, Present: 1, DPL: 0, DB: 0, S: 1, L: 1, G: 1, AVL: 0},
	DS:   segment{Base: 0, Limit: 0xffffffff, Selector: 16, Stype: 3, Present: 1, DPL: 0, DB: 0, S: 1, L: 1, G: 1, AVL: 0},
	ES:   segment{Base: 0, Limit: 0xffffffff, Selector: 16, Stype: 3, Present: 1, DPL: 0, DB: 0, S: 1, L: 1, G: 1, AVL: 0},
	FS:   segment{Base: 0, Limit: 0xffffffff, Selector: 16, Stype: 3, Present: 1, DPL: 0, DB: 0, S: 1, L: 1, G: 1, AVL: 0},
	GS:   segment{Base: 0, Limit: 0xffffffff, Selector: 16, Stype: 3, Present: 1, DPL: 0, DB: 0, S: 1, L: 1, G: 1, AVL: 0},
	SS:   segment{Base: 0, Limit: 0xffffffff, Selector: 16, Stype: 3, Present: 1, DPL: 0, DB: 0, S: 1, L: 1, G: 1, AVL: 0},
	TR:   segment{Base: 0, Limit: 0xffff, Selector: 0, Stype: 3, Present: 1, DPL: 0, DB: 0, S: 0, L: 0, G: 0, AVL: 0},
	LDT:  segment{Base: 0, Limit: 0xffff, Selector: 0, Stype: 2, Present: 1, DPL: 0, DB: 0, S: 0, L: 0, G: 0, AVL: 0},
	GDT:  dtable{Base: 0, Limit: 0xffff},
	IDT:  dtable{Base: 0, Limit: 0xffff},
	CR0:  CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG,
	CR2:  0,
	CR3:  PageTableBase,
	CR4:  CR4_PAE,
	CR8:  0,
	EFER: EFER_LME | EFER_LMA,
	APIC: 0xfee00900,
	/*interrupt_bitmap:[0, 0, 0, 0]*/
}

// reference ...
type signalfdSiginfo struct {
	Signo    uint32
	Errno    int32
	Code     int32
	Pid      uint32
	Uid      uint32
	Fd       int32
	Tid      uint32
	Band     uint32
	Overrun  uint32
	Trapno   uint32
	Status   int32
	Int      int32
	Ptr      uint64
	Utime    uint64
	Stime    uint64
	Addr     uint64
	Addr_lsb uint16

	Syscall   int32
	Call_addr uint64
	Arch      uint32
	// contains filtered or unexported fields
}

// Exit types
/* KVM_EXIT_MMIO */
type xmmio struct {
	Addr  uint64
	Data  [8]byte
	Len   int32
	Write uint8
}

func (x *xmmio) String() string {
	return fmt.Sprintf("Addr %#x Len %#x Write %#x", x.Addr, x.Len, x.Write)
}

const (
	xioIn  = 0
	xioOut = 1
)

type xio struct {
	Dir   uint8
	Size  uint8
	Port  uint16
	Count uint32
	Off   uint64
}

func (x *xio) String() string {
	var op string
	var size string
	switch x.Dir {
	case xioIn:
		op = "in"
	case xioOut:
		op = "out"
	default:
		op = "IOWTF"
	}
	switch x.Size {
	case 1:
		size = "b"
	case 2:
		size = "w"
	case 4:
		size = "l"
	case 8:
		size = "q"
	default:
		size = "sizebad"
	}

	return fmt.Sprintf("[%#x]%s%s %#04x", x.Off, op, size, x.Port)
}

type shutdown struct {
	Stype uint32
	Flags uint64
}

//                 /* KVM_EXIT_SYSTEM_EVENT */
//                 struct {
// #define KVM_SYSTEM_EVENT_SHUTDOWN       1
// #define KVM_SYSTEM_EVENT_RESET          2
// #define KVM_SYSTEM_EVENT_CRASH          3
//                         __u32 type;
//                         __u64 flags;
//                 } system_event;
var stype = map[uint32]string{
	1: "shutdown",
	2: "reset",
	3: "crash",
}

func (t *Tracee) readInfo() error {
	vmr := bytes.NewBuffer(t.cpu.m)
	//Debug("vmr len %d", vmr.Len())
	if err := binary.Read(vmr, binary.LittleEndian, &t.cpu.VMRun); err != nil {
		log.Panicf("Read in run failed -- can't happen")
	}
	//Debug("vmr len %d", vmr.Len())
	r, _, err := t.getRegs()
	if err != nil {
		return fmt.Errorf("readInfo: %v", err)
	}
	e := t.cpu.VMRun.ExitReason
	sig := unix.SignalfdSiginfo{
		Errno:     0,
		Code:      int32(e),
		Pid:       0,
		Uid:       0,
		Fd:        0,
		Tid:       0,
		Band:      0,
		Overrun:   0,
		Trapno:    uint32(e),
		Status:    0,
		Int:       0,
		Ptr:       0,
		Utime:     uint64(time.Now().Unix()),
		Stime:     uint64(time.Now().Unix()),
		Addr:      0,
		Addr_lsb:  0,
		Syscall:   0,
		Call_addr: r.Rip,
		Arch:      0, // no idea
		Signo:     0,
	}

	// Our convention will be that kvm will set the Trapno,
	// and ptrace will set the signo. That makes it easy to
	// figure out how to do the handler.
	switch e {
	case ExitDebug:
		sig.Addr = r.Rip
		Debug("ExitDebug: %#x", r.Rip)
	case ExitHlt:
		sig.Addr = r.Rip
		Debug("ExitHalt: %#x", r.Rip)
	case ExitIo:
		var x xio
		if err := binary.Read(vmr, binary.LittleEndian, &x); err != nil {
			log.Panicf("Read in run failed -- can't happen")
		}
		sig.Addr = uint64(x.Port)
		Debug("ExitIO: Addr '%#x' %s", sig.Addr, x.String())
	case ExitMmio:
		var x xmmio
		if err := binary.Read(vmr, binary.LittleEndian, &x); err != nil {
			log.Panicf("Read in run failed -- can't happen")
		}
		sig.Addr = x.Addr
		Debug("ExitMMiO: Addr '%#x' %s", sig.Addr, x.String())
	case ExitShutdown:
		var x shutdown
		if err := binary.Read(vmr, binary.LittleEndian, &x); err != nil {
			log.Panicf("Read in run failed -- can't happen")
		}
		n, _ := stype[x.Stype]
		Debug("Shutdown: %s [%#x] flags %#x", n, x.Stype, x.Flags)
		//Debug("Shutdown: m[%#x] is %#x", x.Flags, t.tab[0x460000:0x460000+0x1000])
		sig.Addr = r.Rip
	case ExitIntr:
		r, s, err := t.getRegs()
		if err != nil {
			return fmt.Errorf("readInfo: %v", err)
		}
		Debug("Intr: regs %#x sregs %#x", s, r)
	default:
		r, s, err := t.getRegs()
		if err != nil {
			return fmt.Errorf("readInfo: %v", err)
		}
		return fmt.Errorf("readInfo: unhandled exit %s, regs %#x sregs %#x", Exit(e), r, s)
	}
	t.info = sig
	return nil
}

// PC implements PC
func (t *Tracee) PC() (uintptr, error) {
	r, err := t.GetRegs()
	if err != nil {
		return 0, err
	}
	return uintptr(r.Rip), nil
}

// Stack implements Stack
func (t *Tracee) Stack() (uintptr, error) {
	r, err := t.GetRegs()
	if err != nil {
		return 0, err
	}
	return uintptr(r.Rsp), nil
}

// PC implements PC
func (t *Tracee) SetPC(pc uintptr) error {
	r, err := t.GetRegs()
	if err != nil {
		return err
	}
	r.Rip = uint64(pc)
	return t.SetRegs(r)
}

// SetStack implements SetStack
func (t *Tracee) SetStack(sp uintptr) error {
	r, err := t.GetRegs()
	if err != nil {
		return err
	}
	r.Rsp = uint64(sp)
	return t.SetRegs(r)
}
