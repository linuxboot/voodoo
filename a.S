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

.align 4096
.section .efi,"awx"
.space 0x80000000
// gcc -nostdlib -o a -static a.S
// gcc -o a -Ttext=0x100000000 -nostdlib -static a.S
