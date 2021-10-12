package trace

import "syscall"

// SetIPtr sets the instruction pointer for a Tracee.
func SetIPtr(t Trace, addr uintptr) error {
	r, err := t.GetRegs()
	if err != nil {
		return err
	}
	r.Rip = uint64(addr)
	return t.SetRegs(r)
}

// Params sets paramers in %rcx, %rdx
func Params(r *syscall.PtraceRegs, arg0, arg1 uintptr) {
	r.Rcx = uint64(arg0) // ImageHandle for EFI
	r.Rdx = uint64(arg1) // SystemTable
}

// Stack implements Stack
func Stack(r *syscall.PtraceRegs) uintptr {
	return uintptr(r.Rsp)
}

// PC implements PC
func PC(r *syscall.PtraceRegs) uintptr {
	return uintptr(r.Rip)
}

// Flags implement Flags
func Flags(r *syscall.PtraceRegs) uintptr {
	return uintptr(r.Eflags)
}

// SetStack implements SetStack
func SetStack(r *syscall.PtraceRegs, s uintptr) {
	r.Rsp = uint64(s)
}

// SetPC implements SetPC
func SetPC(r *syscall.PtraceRegs, pc uintptr) {
	r.Rip = uint64(pc)
}

// SetFlags implement SetFlags
func SetFlags(r *syscall.PtraceRegs, f uintptr) {
	r.Eflags = uint64(f)
}
