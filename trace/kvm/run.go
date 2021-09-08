// Package kvm provides an interface to the kvm system call.
package kvm

import (
	"fmt"

	"github.com/bobuhiro11/gokvm/kvm"
)

// const (
// 	ExitUnknown       = 0
// 	ExitException     = 1
// 	ExitIO            = 2
// 	ExitHypercall     = 3
// 	ExitDebug         = 4
// 	ExitHlt           = 5
// 	ExitMMIO          = 6
// 	ExitIRQWindowOpen = 7
// 	ExitShutdown      = 8
// 	ExitFailEntry     = 9
// 	ExitIntr          = 10
// 	ExitSetTPR        = 11
// 	ExitTPRAccess     = 12

// 	/* For ExitINTERNALERROR */
// 	/* Emulate instruction failed. */
// 	InternalErrorEmulation = 1
// 	/* Encounter unexpected simultaneous exceptions. */
// 	InternalErrorSimulEX = 2
// 	/* Encounter unexpected vm-exit due to delivery event. */
// 	InternalErrorEeliveryEV = 3
// )

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

func RunString(r *kvm.RunData) string {
	return fmt.Sprintf("%s", Exit(r.ExitReason))
}

/* 		{ */
/* 			union { */
/* 		/\* KVM_EXIT_UNKNOWN *\/ */
/* 		struct { */
/* 			__u64 hardware_exit_reason; */
/* 		} hw; */
/* 		/\* KVM_EXIT_FAIL_ENTRY *\/ */
/* 		struct { */
/* 			__u64 hardware_entry_failure_reason; */
/* 		} fail_entry; */
/* 		/\* KVM_EXIT_EXCEPTION *\/ */
/* 		struct { */
/* 			__u32 exception; */
/* 			__u32 error_code; */
/* 		} ex; */
/* 		/\* KVM_EXIT_IO *\/ */
/* 		struct { */
/* #define KVM_EXIT_IO_IN 0 */
/* #define KVM_EXIT_IO_OUT 1 */
/* 			__u8 direction; */
/* 			__u8 size; /\* bytes *\/ */
/* 			__u16 port; */
/* 			__u32 count; */
/* 			__u64 data_offset; /\* relative to kvm_run start *\/ */
/* 		} io; */
/* 		/\* KVM_EXIT_DEBUG *\/ */
/* 		struct { */
/* 			struct kvm_debug_exit_arch arch; */
/* 		} debug; */
/* 		/\* KVM_EXIT_MMIO *\/ */
/* 		struct { */
/* 			__u64 phys_addr; */
/* 			__u8  data[8]; */
/* 			__u32 len; */
/* 			__u8  is_write; */
/* 		} mmio; */
/* 		/\* KVM_EXIT_HYPERCALL *\/ */
/* 		struct { */
/* 			__u64 nr; */
/* 			__u64 args[6]; */
/* 			__u64 ret; */
/* 			__u32 longmode; */
/* 			__u32 pad; */
/* 		} hypercall; */
/* 		/\* KVM_EXIT_TPR_ACCESS *\/ */
/* 		struct { */
/* 			__u64 rip; */
/* 			__u32 is_write; */
/* 			__u32 pad; */
/* 		} tpr_access; */
/* 		/\* KVM_EXIT_S390_SIEIC *\/ */
/* 		struct { */
/* 			__u8 icptcode; */
/* 			__u16 ipa; */
/* 			__u32 ipb; */
/* 		} s390_sieic; */
/* 		/\* KVM_EXIT_S390_RESET *\/ */
/* #define KVM_S390_RESET_POR 1 */
/* #define KVM_S390_RESET_CLEAR 2 */
/* #define KVM_S390_RESET_SUBSYSTEM 4 */
/* #define KVM_S390_RESET_CPU_INIT 8 */
/* #define KVM_S390_RESET_IPL 16 */
/* 		__u64 s390_reset_flags; */
/* 		/\* KVM_EXIT_S390_UCONTROL *\/ */
/* 		struct { */
/* 			__u64 trans_exc_code; */
/* 			__u32 pgm_code; */
/* 		} s390_ucontrol; */
/* 		/\* KVM_EXIT_DCR (deprecated) *\/ */
/* 		struct { */
/* 			__u32 dcrn; */
/* 			__u32 data; */
/* 			__u8  is_write; */
/* 		} dcr; */
/* 		/\* KVM_EXIT_INTERNAL_ERROR *\/ */
/* 		struct { */
/* 			__u32 suberror; */
/* 			/\* Available with KVM_CAP_INTERNAL_ERROR_DATA: *\/ */
/* 			__u32 ndata; */
/* 			__u64 data[16]; */
/* 		} internal; */
/* 		/\* KVM_EXIT_OSI *\/ */
/* 		struct { */
/* 			__u64 gprs[32]; */
/* 		} osi; */
/* 		/\* KVM_EXIT_PAPR_HCALL *\/ */
/* 		struct { */
/* 			__u64 nr; */
/* 			__u64 ret; */
/* 			__u64 args[9]; */
/* 		} papr_hcall; */
/* 		/\* KVM_EXIT_S390_TSCH *\/ */
/* 		struct { */
/* 			__u16 subchannel_id; */
/* 			__u16 subchannel_nr; */
/* 			__u32 io_int_parm; */
/* 			__u32 io_int_word; */
/* 			__u32 ipb; */
/* 			__u8 dequeued; */
/* 		} s390_tsch; */
/* 		/\* KVM_EXIT_EPR *\/ */
/* 		struct { */
/* 			__u32 epr; */
/* 		} epr; */
/* 		/\* KVM_EXIT_SYSTEM_EVENT *\/ */
/* 		struct { */
/* #define KVM_SYSTEM_EVENT_SHUTDOWN 1 */
/* #define KVM_SYSTEM_EVENT_RESET 2 */
/* #define KVM_SYSTEM_EVENT_CRASH 3 */
/* 			__u32 type; */
/* 			__u64 flags; */
/* 		} system_event; */
/* 		/\* KVM_EXIT_S390_STSI *\/ */
/* 		struct { */
/* 			__u64 addr; */
/* 			__u8 ar; */
/* 			__u8 reserved; */
/* 			__u8 fc; */
/* 			__u8 sel1; */
/* 			__u16 sel2; */
/* 		} s390_stsi; */
/* 		/\* KVM_EXIT_IOAPIC_EOI *\/ */
/* 		struct { */
/* 			__u8 vector; */
/* 		} eoi; */
/* 		/\* KVM_EXIT_HYPERV *\/ */
/* 		struct kvm_hyperv_exit hyperv; */
/* 		/\* Fix the size of the union. *\/ */
/* 		char padding[256]; */
/* 	}; */

/* 	/\* */
/* 	 * shared registers between kvm and userspace. */
/* 	 * kvm_valid_regs specifies the register classes set by the host */
/* 	 * kvm_dirty_regs specified the register classes dirtied by userspace */
/* 	 * struct kvm_sync_regs is architecture specific, as well as the */
/* 	 * bits for kvm_valid_regs and kvm_dirty_regs */
/* 	 *\/ */
/* 	__u64 kvm_valid_regs; */
/* 	__u64 kvm_dirty_regs; */
/* 	union { */
/* 		struct kvm_sync_regs regs; */
/* 		char padding[2048]; */
/* 	} s; */
/* }; */

/* /\* for KVM_TRANSLATE *\/ */
/* struct kvm_translation { */
/* 	/\* in *\/ */
/* 	__u64 linear_address; */

/* 	/\* out *\/ */
/* 	__u64 physical_address; */
/* 	__u8  valid; */
/* 	__u8  writeable; */
/* 	__u8  usermode; */
/* 	__u8  pad[5]; */
/* }; */

/* /\* for KVM_ENABLE_CAP *\/ */
/* struct kvm_enable_cap { */
/* 	/\* in *\/ */
/* 	__u32 cap; */
/* 	__u32 flags; */
/* 	__u64 args[4]; */
/* 	__u8  pad[64]; */
/* }; */

/* /\* */
/*  * ioctls for /dev/kvm fds: */
/*  *\/ */
/* #define KVM_GET_API_VERSION _IO(KVMIO, 0x00) */
/* #define KVM_CREATE_VM _IO(KVMIO, 0x01) /\* returns a VM fd *\/ */
/* #define KVM_GET_MSR_INDEX_LIST _IOWR(KVMIO, 0x02, struct kvm_msr_list) */

/* /\* */
/*  * Check if a kvm extension is available.  Argument is extension number, */
/*  * return is 1 (yes) or 0 (no, sorry). */
/*  *\/ */
/* #define KVM_CHECK_EXTENSION _IO(KVMIO, 0x03) */
/* /\* */
/*  * Get size for mmap(vcpu_fd) */
/*  *\/ */
/* #define KVM_GET_VCPU_MMAP_SIZE _IO(KVMIO, 0x04) /\* in bytes *\/ */
/* #define KVM_GET_SUPPORTED_CPUID _IOWR(KVMIO, 0x05, struct kvm_cpuid2) */
/* #define KVM_TRACE_ENABLE __KVM_DEPRECATED_MAIN_W_0x06 */
/* #define KVM_TRACE_PAUSE __KVM_DEPRECATED_MAIN_0x07 */
/* #define KVM_TRACE_DISABLE __KVM_DEPRECATED_MAIN_0x08 */
/* #define KVM_GET_EMULATED_CPUID _IOWR(KVMIO, 0x09, struct kvm_cpuid2) */

/* /\* */
/*  * Extension capability list. */
/*  *\/ */
/* #define KVM_CAP_IRQCHIP 0 */
/* #define KVM_CAP_HLT 1 */
/* #define KVM_CAP_MMU_SHADOW_CACHE_CONTROL 2 */
/* #define KVM_CAP_USER_MEMORY 3 */
/* #define KVM_CAP_SET_TSS_ADDR 4 */
/* #define KVM_CAP_VAPIC 6 */
/* #define KVM_CAP_EXT_CPUID 7 */
/* #define KVM_CAP_CLOCKSOURCE 8 */
/* #define KVM_CAP_NR_VCPUS 9 /\* returns recommended max vcpus per vm *\/ */
/* #define KVM_CAP_NR_MEMSLOTS 10 /\* returns max memory slots per vm *\/ */
/* #define KVM_CAP_PIT 11 */
/* #define KVM_CAP_NOP_IO_DELAY 12 */
/* #define KVM_CAP_PV_MMU 13 */
/* #define KVM_CAP_MP_STATE 14 */
/* #define KVM_CAP_COALESCED_MMIO 15 */
/* #define KVM_CAP_SYNC_MMU 16 /\* Changes to host mmap are reflected in guest *\/ */
/* #define KVM_CAP_IOMMU 18 */
/* /\* Bug in KVM_SET_USER_MEMORY_REGION fixed: *\/ */
/* #define KVM_CAP_DESTROY_MEMORY_REGION_WORKS 21 */
/* #define KVM_CAP_USER_NMI 22 */
/* #ifdef __KVM_HAVE_GUEST_DEBUG */
/* #define KVM_CAP_SET_GUEST_DEBUG 23 */
/* #endif */
/* #ifdef __KVM_HAVE_PIT */
/* #define KVM_CAP_REINJECT_CONTROL 24 */
/* #endif */
/* #define KVM_CAP_IRQ_ROUTING 25 */
/* #define KVM_CAP_IRQ_INJECT_STATUS 26 */
/* #define KVM_CAP_ASSIGN_DEV_IRQ 29 */
/* /\* Another bug in KVM_SET_USER_MEMORY_REGION fixed: *\/ */
/* #define KVM_CAP_JOIN_MEMORY_REGIONS_WORKS 30 */
/* #ifdef __KVM_HAVE_MCE */
/* #define KVM_CAP_MCE 31 */
/* #endif */
/* #define KVM_CAP_IRQFD 32 */
/* #ifdef __KVM_HAVE_PIT */
/* #define KVM_CAP_PIT2 33 */
/* #endif */
/* #define KVM_CAP_SET_BOOT_CPU_ID 34 */
/* #ifdef __KVM_HAVE_PIT_STATE2 */
/* #define KVM_CAP_PIT_STATE2 35 */
/* #endif */
/* #define KVM_CAP_IOEVENTFD 36 */
/* #define KVM_CAP_SET_IDENTITY_MAP_ADDR 37 */
/* #ifdef __KVM_HAVE_XEN_HVM */
/* #define KVM_CAP_XEN_HVM 38 */
/* #endif */
/* #define KVM_CAP_ADJUST_CLOCK 39 */
/* #define KVM_CAP_INTERNAL_ERROR_DATA 40 */
/* #ifdef __KVM_HAVE_VCPU_EVENTS */
/* #define KVM_CAP_VCPU_EVENTS 41 */
/* #endif */
/* #define KVM_CAP_S390_PSW 42 */
/* #define KVM_CAP_PPC_SEGSTATE 43 */
/* #define KVM_CAP_HYPERV 44 */
/* #define KVM_CAP_HYPERV_VAPIC 45 */
/* #define KVM_CAP_HYPERV_SPIN 46 */
/* #define KVM_CAP_PCI_SEGMENT 47 */
/* #define KVM_CAP_PPC_PAIRED_SINGLES 48 */
/* #define KVM_CAP_INTR_SHADOW 49 */
/* #ifdef __KVM_HAVE_DEBUGREGS */
/* #define KVM_CAP_DEBUGREGS 50 */
/* #endif */
/* #define KVM_CAP_X86_ROBUST_SINGLESTEP 51 */
/* #define KVM_CAP_PPC_OSI 52 */
/* #define KVM_CAP_PPC_UNSET_IRQ 53 */
/* #define KVM_CAP_ENABLE_CAP 54 */
/* #ifdef __KVM_HAVE_XSAVE */
/* #define KVM_CAP_XSAVE 55 */
/* #endif */
/* #ifdef __KVM_HAVE_XCRS */
/* #define KVM_CAP_XCRS 56 */
/* #endif */
/* #define KVM_CAP_PPC_GET_PVINFO 57 */
/* #define KVM_CAP_PPC_IRQ_LEVEL 58 */
/* #define KVM_CAP_ASYNC_PF 59 */
/* #define KVM_CAP_TSC_CONTROL 60 */
/* #define KVM_CAP_GET_TSC_KHZ 61 */
/* #define KVM_CAP_PPC_BOOKE_SREGS 62 */
/* #define KVM_CAP_SPAPR_TCE 63 */
/* #define KVM_CAP_PPC_SMT 64 */
/* #define KVM_CAP_PPC_RMA 65 */
/* #define KVM_CAP_MAX_VCPUS 66 /\* returns max vcpus per vm *\/ */
/* #define KVM_CAP_PPC_HIOR 67 */
/* #define KVM_CAP_PPC_PAPR 68 */
/* #define KVM_CAP_SW_TLB 69 */
/* #define KVM_CAP_ONE_REG 70 */
/* #define KVM_CAP_S390_GMAP 71 */
/* #define KVM_CAP_TSC_DEADLINE_TIMER 72 */
/* #define KVM_CAP_S390_UCONTROL 73 */
/* #define KVM_CAP_SYNC_REGS 74 */
/* #define KVM_CAP_PCI_2_3 75 */
/* #define KVM_CAP_KVMCLOCK_CTRL 76 */
/* #define KVM_CAP_SIGNAL_MSI 77 */
/* #define KVM_CAP_PPC_GET_SMMU_INFO 78 */
/* #define KVM_CAP_S390_COW 79 */
/* #define KVM_CAP_PPC_ALLOC_HTAB 80 */
/* #define KVM_CAP_READONLY_MEM 81 */
/* #define KVM_CAP_IRQFD_RESAMPLE 82 */
/* #define KVM_CAP_PPC_BOOKE_WATCHDOG 83 */
/* #define KVM_CAP_PPC_HTAB_FD 84 */
/* #define KVM_CAP_S390_CSS_SUPPORT 85 */
/* #define KVM_CAP_PPC_EPR 86 */
/* #define KVM_CAP_ARM_PSCI 87 */
/* #define KVM_CAP_ARM_SET_DEVICE_ADDR 88 */
/* #define KVM_CAP_DEVICE_CTRL 89 */
/* #define KVM_CAP_IRQ_MPIC 90 */
/* #define KVM_CAP_PPC_RTAS 91 */
/* #define KVM_CAP_IRQ_XICS 92 */
/* #define KVM_CAP_ARM_EL1_32BIT 93 */
/* #define KVM_CAP_SPAPR_MULTITCE 94 */
/* #define KVM_CAP_EXT_EMUL_CPUID 95 */
/* #define KVM_CAP_HYPERV_TIME 96 */
/* #define KVM_CAP_IOAPIC_POLARITY_IGNORED 97 */
/* #define KVM_CAP_ENABLE_CAP_VM 98 */
/* #define KVM_CAP_S390_IRQCHIP 99 */
/* #define KVM_CAP_IOEVENTFD_NO_LENGTH 100 */
/* #define KVM_CAP_VM_ATTRIBUTES 101 */
/* #define KVM_CAP_ARM_PSCI_0_2 102 */
/* #define KVM_CAP_PPC_FIXUP_HCALL 103 */
/* #define KVM_CAP_PPC_ENABLE_HCALL 104 */
/* #define KVM_CAP_CHECK_EXTENSION_VM 105 */
/* #define KVM_CAP_S390_USER_SIGP 106 */
/* #define KVM_CAP_S390_VECTOR_REGISTERS 107 */
/* #define KVM_CAP_S390_MEM_OP 108 */
/* #define KVM_CAP_S390_USER_STSI 109 */
/* #define KVM_CAP_S390_SKEYS 110 */
/* #define KVM_CAP_MIPS_FPU 111 */
/* #define KVM_CAP_MIPS_MSA 112 */
/* #define KVM_CAP_S390_INJECT_IRQ 113 */
/* #define KVM_CAP_S390_IRQ_STATE 114 */
/* #define KVM_CAP_PPC_HWRNG 115 */
/* #define KVM_CAP_DISABLE_QUIRKS 116 */
/* #define KVM_CAP_X86_SMM 117 */
/* #define KVM_CAP_MULTI_ADDRESS_SPACE 118 */
/* #define KVM_CAP_GUEST_DEBUG_HW_BPS 119 */
/* #define KVM_CAP_GUEST_DEBUG_HW_WPS 120 */
/* #define KVM_CAP_SPLIT_IRQCHIP 121 */
/* #define KVM_CAP_IOEVENTFD_ANY_LENGTH 122 */
/* #define KVM_CAP_HYPERV_SYNIC 123 */
/* #define KVM_CAP_S390_RI 124 */
/* #define KVM_CAP_SPAPR_TCE_64 125 */
/* #define KVM_CAP_ARM_PMU_V3 126 */
/* #define KVM_CAP_VCPU_ATTRIBUTES 127 */
/* #define KVM_CAP_MAX_VCPU_ID 128 */
/* #define KVM_CAP_X2APIC_API 129 */
/* #define KVM_CAP_S390_USER_INSTR0 130 */
/* #define KVM_CAP_MSI_DEVID 131 */
/* #define KVM_CAP_PPC_HTM 132 */
/* #define KVM_CAP_SPAPR_RESIZE_HPT 133 */
/* #define KVM_CAP_PPC_MMU_RADIX 134 */
/* #define KVM_CAP_PPC_MMU_HASH_V3 135 */
/* #define KVM_CAP_IMMEDIATE_EXIT 136 */
