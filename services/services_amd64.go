package services

import (
	"syscall"

	"github.com/linuxboot/voodoo/ptrace"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

// Fault defines all we need to know on a fault and how to do it.
type Fault struct {
	Proc *ptrace.Tracee
	Info *unix.SignalfdSiginfo
	Inst *x86asm.Inst
	Regs *syscall.PtraceRegs
	Args []uint64
}
