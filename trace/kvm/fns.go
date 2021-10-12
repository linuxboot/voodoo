package kvm

import (
	"fmt"
	"reflect"
)

func showone(indent string, in interface{}) string {
	var ret string
	s := reflect.ValueOf(in).Elem()
	typeOfT := s.Type()

	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		switch f.Kind() {
		case reflect.String:
			ret += fmt.Sprintf(indent+"%s %s = %s\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
		default:
			ret += fmt.Sprintf(indent+"%s %s = %#x\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
		}
	}
	return ret
}

func show(indent string, l ...interface{}) string {
	var ret string
	for _, i := range l {
		ret += showone(indent, i)
	}
	return ret
}

// MemoryRegion is used for CREATE_MEMORY_REGION
type MemoryRegion struct {
	Slot  uint32
	Flags uint32
	GPA   uint64
	Size  uint64 /* bytes */
}

// CreateRegion is used for KVM_CREATE_MEMORY_REGION
type CreateRegion struct {
	Slot  uint32
	Flags uint32
	GPA   uint64
	Size  uint64
}

// UserRegion is used for  SET_USER_MEMORY_REGION
type UserRegion struct {
	Slot     uint32
	Flags    uint32
	GPA      uint64
	Size     uint64
	UserAddr uint64
}

/*
 * The bit 0 ~ bit 15 of kvm_memory_region::flags are visible for userspace,
 * other bits are reserved for kvm internal use which are defined in
 * include/linux/kvm_host.h.
 */
//#define MEM_LOG_DIRTY_PAGES	(1UL << 0)
//#define MEM_READONLY	(1UL << 1)

/* For ExitINTERNAL_ERROR */
/* Emulate instruction failed. */
//#define INTERNAL_ERROR_EMULATION	1
/* Encounter unexpected simultaneous exceptions. */
//#define INTERNAL_ERROR_SIMUL_EX	2
/* Encounter unexpected vm-exit due to delivery event. */
//#define INTERNAL_ERROR_DELIVERY_EV	3
/* Encounter unexpected vm-exit reason */
//#define INTERNAL_ERROR_UNEXPECTED_ExitREASON	4

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
