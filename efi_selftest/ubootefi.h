/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Extensible Firmware Interface
 * Based on 'Extensible Firmware Interface Specification' version 0.9,
 * April 30, 1999
 *
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *	Stephane Eranian <eranian@hpl.hp.com>
 *
 * From include/linux/efi.h in kernel 4.1 with some additions/subtractions
 */

#ifndef _UBOOT_EFI_H
#define _UBOOT_EFI_H


/*
 * EFI on x86_64 uses the Microsoft ABI which is not the default for GCC.
 *
 * There are two scenarios for EFI on x86_64: building a 64-bit EFI stub
 * codes (CONFIG_EFI_STUB_64BIT) and building a 64-bit U-Boot (CONFIG_X86_64).
 * Either needs to be properly built with the '-m64' compiler flag, and hence
 * it is enough to only check the compiler provided define __x86_64__ here.
 */
#ifdef __x86_64__
#define EFIAPI __attribute__((ms_abi))
#define efi_va_list __builtin_ms_va_list
#define efi_va_start __builtin_ms_va_start
#define efi_va_arg __builtin_va_arg
#define efi_va_end __builtin_ms_va_end
#else
#define EFIAPI asmlinkage
#define efi_va_list va_list
#define efi_va_start va_start
#define efi_va_arg va_arg
#define efi_va_end va_end
#endif /* __x86_64__ */

#define EFI32_LOADER_SIGNATURE	"EL32"
#define EFI64_LOADER_SIGNATURE	"EL64"

struct efi_device_path;

typedef struct {
	uint8_t b[16];
} efi_guid_t;

#define EFI_BITS_PER_LONG	(sizeof(long) * 8)

/* Bit mask for EFI status code with error */

/* Status codes returned by EFI protocols */
#define EFI_SUCCESS			0


typedef unsigned long efi_status_t;
typedef uint64_t efi_physical_addr_t;
typedef uint64_t efi_virtual_addr_t;
typedef void *efi_handle_t;

// The original u-boot code does not do casts, hence gets errors.
// add casts. 
#define EFI_GUID(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) \
	{{\
			(uint8_t)(a&0xff),				\
				(uint8_t)(((a) >> 8)&0xff),		\
				(uint8_t)(((a) >> 16)&0xff),		\
				(uint8_t)(((a) >> 24) & 0xff),		\
				(uint8_t)(b&0xff),\
				(uint8_t)(((b) >> 8)&0xff),		\
				(uint8_t)(c&0xff),\
				(uint8_t)(((c) >> 8)&0xff),		\
				(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) } }

/* Generic EFI table header */
struct efi_table_hdr {
	uint64_t signature;
	uint32_t revision;
	uint32_t headersize;
	uint32_t crc32;
	uint32_t reserved;
};

/* Enumeration of memory types introduced in UEFI */
enum efi_mem_type {
	EFI_RESERVED_MEMORY_TYPE,
	/*
	 * The code portions of a loaded application.
	 * (Note that UEFI OS loaders are UEFI applications.)
	 */
	EFI_LOADER_CODE,
	/*
	 * The data portions of a loaded application and
	 * the default data allocation type used by an application
	 * to allocate pool memory.
	 */
	EFI_LOADER_DATA,
	/* The code portions of a loaded Boot Services Driver */
	EFI_BOOT_SERVICES_CODE,
	/*
	 * The data portions of a loaded Boot Services Driver and
	 * the default data allocation type used by a Boot Services
	 * Driver to allocate pool memory.
	 */
	EFI_BOOT_SERVICES_DATA,
	/* The code portions of a loaded Runtime Services Driver */
	EFI_RUNTIME_SERVICES_CODE,
	/*
	 * The data portions of a loaded Runtime Services Driver and
	 * the default data allocation type used by a Runtime Services
	 * Driver to allocate pool memory.
	 */
	EFI_RUNTIME_SERVICES_DATA,
	/* Free (unallocated) memory */
	EFI_CONVENTIONAL_MEMORY,
	/* Memory in which errors have been detected */
	EFI_UNUSABLE_MEMORY,
	/* Memory that holds the ACPI tables */
	EFI_ACPI_RECLAIM_MEMORY,
	/* Address space reserved for use by the firmware */
	EFI_ACPI_MEMORY_NVS,
	/*
	 * Used by system firmware to request that a memory-mapped IO region
	 * be mapped by the OS to a virtual address so it can be accessed by
	 * EFI runtime services.
	 */
	EFI_MMAP_IO,
	/*
	 * System memory-mapped IO region that is used to translate
	 * memory cycles to IO cycles by the processor.
	 */
	EFI_MMAP_IO_PORT,
	/*
	 * Address space reserved by the firmware for code that is
	 * part of the processor.
	 */
	EFI_PAL_CODE,

	EFI_MAX_MEMORY_TYPE,
	EFI_TABLE_END,	/* For efi_build_mem_table() */
};

/* Attribute values */

struct efi_mem_desc {
	uint32_t type;
	uint32_t reserved;
	efi_physical_addr_t physical_start;
	efi_virtual_addr_t virtual_start;
	uint64_t num_pages;
	uint64_t attribute;
};

#define EFI_MEMORY_DESCRIPTOR_VERSION 1

/* Allocation types for calls to boottime->allocate_pages*/
#define EFI_ALLOCATE_ANY_PAGES		0
#define EFI_ALLOCATE_MAX_ADDRESS	1
#define EFI_ALLOCATE_ADDRESS		2
#define EFI_MAX_ALLOCATE_TYPE		3

/* Types and defines for Time Services */

struct efi_time {
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	uint8_t pad1;
	uint32_t nanosecond;
	int16_t timezone;
	uint8_t daylight;
	uint8_t pad2;
};

struct efi_time_cap {
	uint32_t resolution;
	uint32_t accuracy;
	uint8_t sets_to_zero;
};

enum efi_locate_search_type {
	ALL_HANDLES,
	BY_REGISTER_NOTIFY,
	BY_PROTOCOL
};

struct efi_open_protocol_info_entry {
	EFI_HANDLE agent_handle;
	EFI_HANDLE controller_handle;
	uint32_t attributes;
	uint32_t open_count;
};

enum efi_entry_t {
	EFIET_END,	/* Signals this is the last (empty) entry */
	EFIET_MEMORY_MAP,
	EFIET_GOP_MODE,
	EFIET_SYS_TABLE,

	/* Number of entries */
	EFIET_MEMORY_COUNT,
};

#define EFI_TABLE_VERSION	1

/**
 * struct efi_info_hdr - Header for the EFI info table
 *
 * @version:	EFI_TABLE_VERSION
 * @hdr_size:	Size of this struct in bytes
 * @total_size:	Total size of this header plus following data
 * @spare:	Spare space for expansion
 */
struct efi_info_hdr {
	uint32_t version;
	uint32_t hdr_size;
	uint32_t total_size;
	uint32_t spare[5];
};

/**
 * struct efi_entry_hdr - Header for a table entry
 *
 * @type:	enum eft_entry_t
 * @size	size of entry bytes excluding header and padding
 * @addr:	address of this entry (0 if it follows the header )
 * @link:	size of entry including header and padding
 * @spare1:	Spare space for expansion
 * @spare2:	Spare space for expansion
 */
struct efi_entry_hdr {
	uint32_t type;
	uint32_t size;
	uint64_t addr;
	uint32_t link;
	uint32_t spare1;
	uint64_t spare2;
};

/**
 * struct efi_entry_memmap - a memory map table passed to U-Boot
 *
 * @version:	EFI's memory map table version
 * @desc_size:	EFI's size of each memory descriptor
 * @spare:	Spare space for expansion
 * @desc:	An array of descriptors, each @desc_size bytes apart
 */
struct efi_entry_memmap {
	uint32_t version;
	uint32_t desc_size;
	uint64_t spare;
	struct efi_mem_desc desc[];
};

/**
 * struct efi_entry_gopmode - a GOP mode table passed to U-Boot
 *
 * @fb_base:	EFI's framebuffer base address
 * @fb_size:	EFI's framebuffer size
 * @info_size:	GOP mode info structure size
 * @info:	Start address of the GOP mode info structure
 */
struct efi_entry_gopmode {
	efi_physical_addr_t fb_base;
	/*
	 * Not like the ones in 'struct efi_gop_mode' which are 'unsigned
	 * long', @fb_size and @info_size have to be 'u64' here. As the EFI
	 * stub codes may have different bit size from the U-Boot payload,
	 * using 'long' will cause mismatch between the producer (stub) and
	 * the consumer (payload).
	 */
	uint64_t fb_size;
	uint64_t info_size;
	/*
	 * We cannot directly use 'struct efi_gop_mode_info info[]' here as
	 * it causes compiler to complain: array type has incomplete element
	 * type 'struct efi_gop_mode_info'.
	 */
	struct /* efi_gop_mode_info */ {
		uint32_t version;
		uint32_t width;
		uint32_t height;
		uint32_t pixel_format;
		uint32_t pixel_bitmask[4];
		uint32_t pixels_per_scanline;
	} info[];
};

/**
 * struct efi_entry_systable - system table passed to U-Boot
 *
 * @sys_table:	EFI system table address
 */
struct efi_entry_systable {
	efi_physical_addr_t sys_table;
};

static inline struct efi_mem_desc *efi_get_next_mem_desc(
		struct efi_entry_memmap *map, struct efi_mem_desc *desc)
{
	return (struct efi_mem_desc *)((unsigned long long)desc + map->desc_size);
}

struct efi_priv {
	EFI_HANDLE parent_image;
	struct efi_device_path *device_path;
	struct efi_system_table *sys_table;
	struct efi_boot_services *boot;
	struct efi_runtime_services *run;
	int use_pool_for_malloc;
	unsigned long ram_base;
	unsigned int image_data_type;
	struct efi_info_hdr *info;
	unsigned int info_size;
	void *next_hdr;
};

/* Base address of the EFI image */
extern char image_base[];

/* Start and end of U-Boot image (for payload) */
extern char _binary_u_boot_bin_start[], _binary_u_boot_bin_end[];

/*
 * Variable Attributes
 */

#define EFI_VARIABLE_MASK	(EFI_VARIABLE_NON_VOLATILE | \
				EFI_VARIABLE_BOOTSERVICE_ACCESS | \
				EFI_VARIABLE_RUNTIME_ACCESS | \
				EFI_VARIABLE_HARDWARE_ERROR_RECORD | \
				EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS | \
				EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | \
				EFI_VARIABLE_APPEND_WRITE)

/**
 * efi_get_sys_table() - Get access to the main EFI system table
 *
 * @return pointer to EFI system table
 */

struct efi_system_table *efi_get_sys_table(void);

/**
 * efi_get_ram_base() - Find the base of RAM
 *
 * This is used when U-Boot is built as an EFI application.
 *
 * @return the base of RAM as known to U-Boot
 */
unsigned long efi_get_ram_base(void);

/**
 * efi_init() - Set up ready for use of EFI boot services
 *
 * @priv:	Pointer to our private EFI structure to fill in
 * @banner:	Banner to display when starting
 * @image:	The image handle passed to efi_main()
 * @sys_table:	The EFI system table pointer passed to efi_main()
 */
int efi_init(struct efi_priv *priv, const char *banner, EFI_HANDLE image,
	     struct efi_system_table *sys_table);

/**
 * efi_malloc() - Allocate some memory from EFI
 *
 * @priv:	Pointer to private EFI structure
 * @size:	Number of bytes to allocate
 * @retp:	Return EFI status result
 * @return pointer to memory allocated, or NULL on error
 */
void *efi_malloc(struct efi_priv *priv, int size, EFI_STATUS *retp);

/**
 * efi_free() - Free memory allocated from EFI
 *
 * @priv:	Pointer to private EFI structure
 * @ptr:	Pointer to memory to free
 */
void efi_free(struct efi_priv *priv, void *ptr);

/**
 * efi_puts() - Write out a string to the EFI console
 *
 * @priv:	Pointer to private EFI structure
 * @str:	String to write (note this is a ASCII, not unicode)
 */
void efi_puts(struct efi_priv *priv, const char *str);

/**
 * efi_putc() - Write out a character to the EFI console
 *
 * @priv:	Pointer to private EFI structure
 * @ch:		Character to write (note this is not unicode)
 */
void efi_putc(struct efi_priv *priv, const char ch);

/**
 * efi_info_get() - get an entry from an EFI table
 *
 * @type:	Entry type to search for
 * @datap:	Returns pointer to entry data
 * @sizep:	Returns pointer to entry size
 * @return 0 if OK, -ENODATA if there is no table, -ENOENT if there is no entry
 * of the requested type, -EPROTONOSUPPORT if the table has the wrong version
 */
int efi_info_get(enum efi_entry_t type, void **datap, int *sizep);

/**
 * efi_build_mem_table() - make a sorted copy of the memory table
 *
 * @map:	Pointer to EFI memory map table
 * @size:	Size of table in bytes
 * @skip_bs:	True to skip boot-time memory and merge it with conventional
 *		memory. This will significantly reduce the number of table
 *		entries.
 * @return pointer to the new table. It should be freed with free() by the
 *	   caller
 */
void *efi_build_mem_table(struct efi_entry_memmap *map, int size, int skip_bs);

#endif /* _LINUX_EFI_H */
