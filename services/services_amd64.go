package services

// Fault defines all we need to know on a fault and how to do it.
type Fault struct {
	Proc *ptrace.Tracee
	Info *unix.SignalfdSiginfo
	Inst *x86asm.Inst
	Regs *syscall.PtraceRegs
	Args []uint64
}
