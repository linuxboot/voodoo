package services

import (
	"fmt"
	"syscall"

	"github.com/linuxboot/voodoo/trace"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/sys/unix"
)

type Register = arm64asm.Reg

// Fault defines all we need to know on a fault and how to do it.
type Fault struct {
	Proc trace.Trace
	Info *unix.SignalfdSiginfo
	Inst *arm64asm.Inst
	Regs *syscall.PtraceRegs
	// We use Asm to figure out instruction type.
	Asm  string
	Args []uintptr
	Op   Func
}

func retval(f *Fault, val uintptr) error {
	panic("retval")
	var err error
	//v := uint64(val)
	switch f.Inst.Args[0] {
	// case x86asm.RSI:
	// 	f.Regs.Rsi = v
	// case x86asm.RCX:
	// 	f.Regs.Rcx = v
	// case x86asm.RDX:
	// 	f.Regs.Rdx = v
	// case x86asm.EDX:
	// 	f.Regs.Rdx = v
	// case x86asm.RAX:
	// 	f.Regs.Rax = v
	// case x86asm.R8:
	// 	f.Regs.R8 = v
	default:
		err = fmt.Errorf("Can't handle dest %v", f.Inst.Args[0])
	}
	return err
}

// SetEFIRetval sets the EFI return value
func (f *Fault) SetEFIRetval(val uintptr) {
	f.Regs.Regs[0] = uint64(val)
}

// GetEFIRetval sets the EFI return value
func (f *Fault) GetEFIRetval() uintptr {
	return uintptr(f.Regs.Regs[0])
}
