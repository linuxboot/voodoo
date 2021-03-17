package trace

import "syscall"

// SetIPtr sets the instruction pointer for a Tracee.
func SetIPtr(t Trace, addr uintptr) error {
	var regs syscall.PtraceRegs
	r, err := t.GetRegs()
	if err != nil {
		return err
	}
	regs.Rip = uint64(addr)
	return t.SetRegs(r)
}
