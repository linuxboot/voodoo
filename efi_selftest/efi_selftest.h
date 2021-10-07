/* SPDX-License-Identifier: GPL-2.0+ */
/*
 *  EFI application loader
 *
 *  Copyright (c) 2017 Heinrich Schuchardt <xypron.glpk@gmx.de>
 */

#ifndef _EFI_SELFTEST_H
#define _EFI_SELFTEST_H

#include <sys/types.h>
#include <stdint.h>
// why the FUCK
typedef unsigned int uint;
// Shit we don't want to include the universe to get
/* this is a special 64bit data type that is 8-byte aligned */
#define aligned_uint64_t uint64_t __aligned(8)
#define aligned_le64 uint64_t __aligned(8)
#define __aligned(x)			__attribute__((aligned(x)))
#define __packed			__attribute__((packed))

#include <efi.h>
#include <efilib.h>
#include <linker_lists.h>

#include <ubootefi.h>
#include <ubootefi_api.h>
#define EFI_ST_SUCCESS 0
#define EFI_ST_FAILURE 1

/*
 * Prints a message.
 */
/*#define efi_st_printf(...)			\
	(efi_st_printc(-1, __VA_ARGS__))
*/
/*
 * Prints an error message.
 *
 * @...	format string followed by fields to print
 */
#define efi_st_error(...) \
	(Print(L"%E%s(%u):\nERROR: ", __FILE__, __LINE__), \
	 Print(__VA_ARGS__),				   \
	 Print(L"%N\n"))

/*
 * Prints a TODO message.
 *
 * @...	format string followed by fields to print
 */
#define efi_st_todo(...) \
	(Print(L"%V%s(%u):\nTODO: ", __FILE__, __LINE__),	\
	 Print(L __VA_ARGS__),						\
	 Print(L"%N"))							\

/*
 * A test may be setup and executed at boottime,
 * it may be setup at boottime and executed at runtime,
 * or it may be setup and executed at runtime.
 */
enum efi_test_phase {
	EFI_EXECUTE_BEFORE_BOOTTIME_EXIT = 1,
	EFI_SETUP_BEFORE_BOOTTIME_EXIT,
	EFI_SETUP_AFTER_BOOTTIME_EXIT,
};

extern struct efi_simple_text_output_protocol *con_out;
extern struct efi_simple_text_input_protocol *con_in;

/*
 * Exit the boot services.
 *
 * The size of the memory map is determined.
 * Pool memory is allocated to copy the memory map.
 * The memory amp is copied and the map key is obtained.
 * The map key is used to exit the boot services.
 */
void efi_st_exit_boot_services(void);

/*
 * Print a colored message
 *
 * @color	color, see constants in efi_api.h, use -1 for no color
 * @fmt		printf format
 * @...		arguments to be printed
 *		on return position of terminating zero word
 */
//void efi_st_printc(int color, const char *fmt, ...)
//		 __attribute__ ((format (__printf__, 2, 3)));
/**
 * efi_st_translate_char() - translate a unicode character to a string
 *
 * @code:	unicode character
 * Return:	string
 */
uint16_t *efi_st_translate_char(uint16_t code);

/**
 * efi_st_translate_code() - translate a scan code to a human readable string
 *
 * @code:	unicode character
 * Return:	string
 */
uint16_t *efi_st_translate_code(uint16_t code);

/*
 * Compare memory.
 * We cannot use lib/string.c due to different CFLAGS values.
 *
 * @buf1:	first buffer
 * @buf2:	second buffer
 * @length:	number of bytes to compare
 * @return:	0 if both buffers contain the same bytes
 */
int efi_st_memcmp(const void *buf1, const void *buf2, size_t length);

/*
 * Compare an u16 string to a char string.
 *
 * @buf1:	u16 string
 * @buf2:	char string
 * @return:	0 if both buffers contain the same bytes
 */
int efi_st_strcmp_16_8(const uint16_t *buf1, const char *buf2);

/*
 * Reads an Unicode character from the input device.
 *
 * @return: Unicode character
 */
uint16_t efi_st_get_key(void);

/**
 * struct efi_unit_test - EFI unit test
 *
 * An efi_unit_test provides a interface to an EFI unit test.
 *
 * @name:	name of unit test
 * @phase:	specifies when setup and execute are executed
 * @setup:	set up the unit test
 * @teardown:	tear down the unit test
 * @execute:	execute the unit test
 * @setup_ok:	setup was successful (set at runtime)
 * @on_request:	test is only executed on request
 */
struct efi_unit_test {
	const char *name;
	const enum efi_test_phase phase;
	int (*setup)(const EFI_HANDLE handle,
		     const EFI_SYSTEM_TABLE *systable);
	int (*execute)(void);
	int (*teardown)(void);
	int setup_ok;
	int on_request;
};

/* Declare a new EFI unit test */
#define EFI_UNIT_TEST(__name)						\
	ll_entry_declare(struct efi_unit_test, __name, efi_unit_test)

#endif /* _EFI_SELFTEST_H */
