package uefi

//
// Memory
//

type paddr uint64
type vaddr uint64

// allocate types
// They made the cardinal mistake of using 0-based contiguous range.
const (
	AllocateAnyPages = iota
	AllocateMaxAddress
	AllocateAddress
	MaxAllocateType
)

// Random UEFI comment
//Preseve the attr on any range supplied.
//ConventialMemory must have WB,SR,SW when supplied.
//When allocating from ConventialMemory always make it WB,SR,SW
//When returning to ConventialMemory always make it WB,SR,SW
//When getting the memory map, or on RT for runtime types

const (
	EfiReservedMemoryType = iota
	EfiLoaderCode
	EfiLoaderData
	EfiBootServicesCode
	EfiBootServicesData
	EfiRuntimeServicesCode
	EfiRuntimeServicesData
	EfiConventionalMemory
	EfiUnusableMemory
	EfiACPIReclaimMemory
	EfiACPIMemoryNVS
	EfiMemoryMappedIO
	EfiMemoryMappedIOPortSpace
	EfiPalCode
	EfiMaxMemoryType = EfiPalCode
)

// possible caching types for the memory range
// Caching Types
const (
	UC = 1 << iota
	WC
	WT
	WB
	UCE
)

const (
	// physical memory protection on range
	WP = 1 << (iota + 12)
	RP
	XP
	All = RP | WP | XP
)

const (
	// range requires a runtime mapping
	RequiresRuntimeMapping = 0x8000000000000000
	// The memory descriptor version -- always 1.
	MemoryDescriptorVersion = 1
)

// MemRegion defines a single UEFI memory region
type MemRegion struct {
	MType  uint32 // Field size is 32 bits followed by 32 bit pad
	_      uint32
	PA     paddr
	VA     vaddr
	Npages uint64
	Attr   uint64
}
