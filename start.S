.code32
1: jmp 1b
.section .ptrace,"awx"
.fill 0x80000000, 0x0f0b, 2
//
// Tear open a Giant Fucking Hole so that any ptrace writes will be ok.
// gcc -static -nostdlib -o binstart start.S

