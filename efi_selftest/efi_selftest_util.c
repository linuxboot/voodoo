// SPDX-License-Identifier: GPL-2.0+
/*
 * efi_selftest_util
 *
 * Copyright (c) 2017 Heinrich Schuchardt <xypron.glpk@gmx.de>
 *
 * Utility functions
 */

#include <efi_selftest.h>

struct efi_st_translate {
	uint16_t code;
	uint16_t *text;
};

static struct efi_st_translate efi_st_control_characters[] = {
	{0, L"Null"},
	{8, L"BS"},
	{9, L"TAB"},
	{10, L"LF"},
	{13, L"CR"},
	{0, NULL},
};

static uint16_t efi_st_ch[] = L"' '";
static uint16_t efi_st_unknown[] = L"unknown";

static struct efi_st_translate efi_st_scan_codes[] = {
	{0x00, L"Null"},
	{0x01, L"Up"},
	{0x02, L"Down"},
	{0x03, L"Right"},
	{0x04, L"Left"},
	{0x05, L"Home"},
	{0x06, L"End"},
	{0x07, L"Insert"},
	{0x08, L"Delete"},
	{0x09, L"Page Up"},
	{0x0a, L"Page Down"},
	{0x0b, L"FN 1"},
	{0x0c, L"FN 2"},
	{0x0d, L"FN 3"},
	{0x0e, L"FN 4"},
	{0x0f, L"FN 5"},
	{0x10, L"FN 6"},
	{0x11, L"FN 7"},
	{0x12, L"FN 8"},
	{0x13, L"FN 9"},
	{0x14, L"FN 10"},
	{0x15, L"FN 11"},
	{0x16, L"FN 12"},
	{0x17, L"Escape"},
	{0x68, L"FN 13"},
	{0x69, L"FN 14"},
	{0x6a, L"FN 15"},
	{0x6b, L"FN 16"},
	{0x6c, L"FN 17"},
	{0x6d, L"FN 18"},
	{0x6e, L"FN 19"},
	{0x6f, L"FN 20"},
	{0x70, L"FN 21"},
	{0x71, L"FN 22"},
	{0x72, L"FN 23"},
	{0x73, L"FN 24"},
	{0x7f, L"Mute"},
	{0x80, L"Volume Up"},
	{0x81, L"Volume Down"},
	{0x100, L"Brightness Up"},
	{0x101, L"Brightness Down"},
	{0x102, L"Suspend"},
	{0x103, L"Hibernate"},
	{0x104, L"Toggle Display"},
	{0x105, L"Recovery"},
	{0x106, L"Reject"},
	{0x0, NULL},
};

uint16_t *efi_st_translate_char(uint16_t code)
{
	struct efi_st_translate *tr;

	if (code >= ' ') {
		efi_st_ch[1] = code;
		return efi_st_ch;
	}
	for (tr = efi_st_control_characters; tr->text; ++tr) {
		if (tr->code == code)
			return tr->text;
	}
	return efi_st_unknown;
}

uint16_t *efi_st_translate_code(uint16_t code)
{
	struct efi_st_translate *tr;

	for (tr = efi_st_scan_codes; tr->text; ++tr) {
		if (tr->code == code)
			return tr->text;
	}
	return efi_st_unknown;
}

int efi_st_memcmp(const void *buf1, const void *buf2, size_t length)
{
	const uint8_t *pos1 = buf1;
	const uint8_t *pos2 = buf2;

	for (; length; --length) {
		if (*pos1 != *pos2)
			return *pos1 - *pos2;
		++pos1;
		++pos2;
	}
	return 0;
}

int efi_st_strcmp_16_8(const uint16_t *buf1, const char *buf2)
{
	for (; *buf1 || *buf2; ++buf1, ++buf2) {
		if (*buf1 != *buf2)
			return *buf1 - *buf2;
	}
	return 0;
}
