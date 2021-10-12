package trace

import "syscall"

// SetIPtr sets the instruction pointer for a Tracee.
func SetIPtr(t Trace, addr uintptr) error {
	r, err := t.GetRegs()
	if err != nil {
		return err
	}
	r.Pc = uint64(addr)
	return t.SetRegs(r)
}

// Params sets paramers in %rcx, %rdx
func Params(r *syscall.PtraceRegs, arg0, arg1 uintptr) {
	r.Regs[0] = uint64(arg0) // ImageHandle for EFI
	r.Regs[1] = uint64(arg1) // SystemTable
}
