// SPDX-License-Identifier: GPL-2.0+
/*
 * EFI efi_selftest
 *
 * Copyright (c) 2017 Heinrich Schuchardt <xypron.glpk@gmx.de>
 */

#include <efi_selftest.h>
#include <vsprintf.h>

struct efi_simple_text_output_protocol *con_out;
struct efi_simple_text_input_protocol *con_in;

/*
 * Print a MAC address to an u16 string
 *
 * @pointer: mac address
 * @buf: pointer to buffer address
 * on return position of terminating zero word
 */
static void mac(void *pointer, uint16_t **buf)
{
	int i, j;
	uint16_t c;
	uint8_t *p = (uint8_t *)pointer;
	uint8_t byte;
	uint16_t *pos = *buf;

	for (i = 0; i < ARP_HLEN; ++i) {
		if (i)
			*pos++ = ':';
		byte = p[i];
		for (j = 4; j >= 0; j -= 4) {
			c = (byte >> j) & 0x0f;
			c += '0';
			if (c > '9')
				c += 'a' - '9' - 1;
			*pos++ = c;
		}
	}
	*pos = 0;
	*buf = pos;
}

/*
 * Print a pointer to an u16 string
 *
 * @pointer: pointer
 * @buf: pointer to buffer address
 * on return position of terminating zero word
 */
static void pointer(void *pointer, uint16_t **buf)
{
	int i;
	uint16_t c;
	uintptr_t p = (uintptr_t)pointer;
	uint16_t *pos = *buf;

	for (i = 8 * sizeof(p) - 4; i >= 0; i -= 4) {
		c = (p >> i) & 0x0f;
		c += '0';
		if (c > '9')
			c += 'a' - '9' - 1;
		*pos++ = c;
	}
	*pos = 0;
	*buf = pos;
}

/*
 * Print an unsigned 32bit value as decimal number to an u16 string
 *
 * @value:	value to be printed
 * @prec:	minimum number of digits to display
 * @buf:	pointer to buffer address
 *		on return position of terminating zero word
 */
static void uint2dec(uint32_t value, int prec, uint16_t **buf)
{
	uint16_t *pos = *buf;
	int i;
	uint16_t c;
	uint64_t f;

	/*
	 * Increment by .5 and multiply with
	 * (2 << 60) / 1,000,000,000 = 0x44B82FA0.9B5A52CC
	 * to move the first digit to bit 60-63.
	 */
	f = 0x225C17D0;
	f += (0x9B5A52DULL * value) >> 28;
	f += 0x44B82FA0ULL * value;

	for (i = 0; i < 10; ++i) {
		/* Write current digit */
		c = f >> 60;
		if (c || pos != *buf || 10 - i <= prec)
			*pos++ = c + '0';
		/* Eliminate current digit */
		f &= 0xfffffffffffffff;
		/* Get next digit */
		f *= 0xaULL;
	}
	if (pos == *buf)
		*pos++ = '0';
	*pos = 0;
	*buf = pos;
}

/*
 * Print a signed 32bit value as decimal number to an u16 string
 *
 * @value:	value to be printed
 * @prec:	minimum number of digits to display
 * @buf:	pointer to buffer address
 * on return position of terminating zero word
 */
static void int2dec(s32 value, int prec, uint16_t **buf)
{
	uint32_t u;
	uint16_t *pos = *buf;

	if (value < 0) {
		*pos++ = '-';
		u = -value;
	} else {
		u = value;
	}
	uint2dec(u, prec, &pos);
	*buf = pos;
}

/*
 * Print a colored formatted string to the EFI console
 *
 * @color	color, see constants in efi_api.h, use -1 for no color
 * @fmt		format string
 * @...		optional arguments
 */
void Print(/*int color*/L const char *fmt, ...)
{
	va_list args;
	uint16_t buf[160];
	const char *c;
	uint16_t *pos = buf;
	const char *s;
	uint16_t *u;
	int prec;

	va_start(args, fmt);

	if (color >= 0)
		con_out->set_attribute(con_out, (unsigned long)color);
	c = fmt;
	for (; *c; ++c) {
		switch (*c) {
		case '\\':
			++c;
			switch (*c) {
			case '\0':
				--c;
				break;
			case 'n':
				*pos++ = '\n';
				break;
			case 'r':
				*pos++ = '\r';
				break;
			case 't':
				*pos++ = '\t';
				break;
			default:
				*pos++ = *c;
			}
			break;
		case '%':
			++c;
			/* Parse precision */
			if (*c == '.') {
				++c;
				prec = *c - '0';
				++c;
			} else {
				prec = 0;
			}
			switch (*c) {
			case '\0':
				--c;
				break;
			case 'd':
				int2dec(va_arg(args, s32), prec, &pos);
				break;
			case 'p':
				++c;
				switch (*c) {
				/* MAC address */
				case 'm':
					mac(va_arg(args, void*), &pos);
					break;

				/* u16 string */
				case 's':
					u = va_arg(args, uint16_t*);
					if (pos > buf) {
						*pos = 0;
						con_out->output_string(con_out,
								       buf);
					}
					con_out->output_string(con_out, u);
					pos = buf;
					break;
				default:
					--c;
					pointer(va_arg(args, void*), &pos);
				}
				break;
			case 's':
				s = va_arg(args, const char *);
				for (; *s; ++s)
					*pos++ = *s;
				break;
			case 'u':
				uint2dec(va_arg(args, uint32_t), prec, &pos);
				break;
			default:
				break;
			}
			break;
		default:
			*pos++ = *c;
		}
	}
	va_end(args);
	*pos = 0;
	con_out->output_string(con_out, buf);
	if (color >= 0)
		con_out->set_attribute(con_out, EFI_LIGHTGRAY);
}

/*
 * Reads an Unicode character from the input device.
 *
 * @return: Unicode character
 */
uint16_t efi_st_get_key(void)
{
	struct efi_input_key input_key;
	EFI_STATUS ret;

	/* Wait for next key */
	do {
		ret = con_in->read_key_stroke(con_in, &input_key);
	} while (ret == EFI_NOT_READY);
	return input_key.unicode_char;
}
