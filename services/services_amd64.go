package services

import (
	"fmt"
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
	Args []uintptr
}

func retval(f *Fault, val uintptr) error {
	var err error
	v := uint64(val)
	switch f.Inst.Args[0] {
	case x86asm.RCX:
		f.Regs.Rcx = v
	case x86asm.RDX:
		f.Regs.Rdx = v
	case x86asm.RAX:
		f.Regs.Rax = v
	case x86asm.R8:
		f.Regs.R8 = v
	default:
		err = fmt.Errorf("Can't handle dest %v", f.Inst.Args[0])
	}
	return err
}
