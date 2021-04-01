.org 0x100000000
.text

.globl _start
_start:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
jmp _start

.section .efi,"awx"
.space 0x80000000
// gcc -nostdlib -o a -static a.S
