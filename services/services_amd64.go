package services

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/linuxboot/voodoo/trace"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

type Register = x86asm.Reg

// Fault defines all we need to know on a fault and how to do it.
type Fault struct {
	Proc trace.Trace
	Info *unix.SignalfdSiginfo
	Inst *x86asm.Inst
	Regs *syscall.PtraceRegs
	// We use Asm to figure out instruction type.
	Asm  string
	Args []uintptr
	Op   Func
}

func retval(f *Fault, val uintptr) error {
	var err error
	v := uint64(val)
	switch f.Inst.Args[0] {
	case x86asm.RSI:
		f.Regs.Rsi = v
	case x86asm.RCX:
		f.Regs.Rcx = v
	case x86asm.RDX:
		f.Regs.Rdx = v
	case x86asm.EDX:
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

// SetEFIRetval sets the EFI return value
func (f *Fault) SetEFIRetval(val uintptr) {
	f.Regs.Rax = uint64(val)
}

// GetEFIRetval sets the EFI return value
func (f *Fault) GetEFIRetval() uintptr {
	return uintptr(f.Regs.Rax)
}

// InstallProtocolStructValue installs a value in a protocol struct.
// We do not transparently use the protocol structs, since they
// follow rules set by MSVC and I'm not sure it's good to just
// blindly use them.
func InstallProtocolStructValue(tab []byte, base int, index uint64, value uint64) {
	x := base + int(index)
	binary.LittleEndian.PutUint64(tab[x:], uint64(value))
	Debug("Install %#x at off %#x", value, x)
}

// InstallUEFICall install a pointer from a protocol struct to the
// code that exits from the virtual machine to RunDXERun.
// It gets slightly complicated if the call is more than 64 bits,
// but not overly so.
func InstallUEFICall(tab []byte, base int, index uint64) {
	r := index + 0xff400000 + uint64(base)
	InstallProtocolStructValue(tab, base, index, r)
}
