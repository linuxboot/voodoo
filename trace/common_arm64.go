package trace

import (
	"encoding/binary"
	"fmt"
	"log"
	"syscall"

	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

// Args returns the top nargs args, going down the stack if needed. The max is 6.
// This is UEFI calling convention.
func Args(t Trace, r *syscall.PtraceRegs, nargs int) []uintptr {
	sp := uintptr(r.Sp)
	log.Panicf("Args sp %#x", sp)
	return []uintptr{}
}

// Pointer returns the data pointed to by args[arg]
func Pointer(t Trace, inst *x86asm.Inst, r *syscall.PtraceRegs, arg int) (uintptr, error) {
	return 0, nil
}

// Pop pops the stack and returns what was at TOS.
func Pop(t Trace, r *syscall.PtraceRegs) (uint64, error) {
	cpc, err := t.ReadWord(uintptr(r.Sp))
	if err != nil {
		return 0, err
	}
	r.Sp += 8
	return cpc, nil
}

// GetReg gets a register value from the Tracee.
// This code does not do any ptrace calls to get registers.
// It returns a pointer so the register can be read and modified.
func GetReg(r *syscall.PtraceRegs, reg int) (*uint64, error) {
	panic("GetReg")
	return nil, fmt.Errorf("Can get %v", reg)
}

var (
	// GenregsPrint is for general purpose registers.
	GenregsPrint = []rprint{}
	// AllregsPrint is for all registers, even useless ones.
	AllregsPrint = append(GenregsPrint,
		[]rprint{}...)
	// RegsPrint allows for selecting which regs to print
	RegsPrint = GenregsPrint
)

// Inst retrieves an instruction from the traced process.
// It returns an x86asm.Inst, Ptraceregs, a string in GNU syntax, and
// and error
// It gets messy if the Rip is in unaddressable space; that means we
// must fetch the saved Rip from [Rsp].
func Inst(t Trace) (*x86asm.Inst, *syscall.PtraceRegs, string, error) {
	r, err := t.GetRegs()
	if err != nil {
		return nil, nil, "", fmt.Errorf("Inst:Getregs:%v", err)
	}
	pc := r.Pc
	sp := r.Sp
	Debug("Inst: pc %#x, sp %#x", pc, sp)
	log.Panicf("Inst: pc %#x, sp %#x", pc, sp)

	return nil, r, "", nil
}

// Asm returns a string for the given instruction at the given pc
func Asm(d *x86asm.Inst, pc uint64) string {
	return "\"" + x86asm.GNUSyntax(*d, pc, nil) + "\""
}

// CallInfo provides calling info for a function.
func CallInfo(_ *unix.SignalfdSiginfo, inst *x86asm.Inst, r *syscall.PtraceRegs) string {
	l := fmt.Sprintf("%s[", show("", r))
	for _, a := range inst.Args {
		l += fmt.Sprintf("%v,", a)
	}
	l += fmt.Sprintf("(%#x, %#x, %#x, %#x)", r.Regs[0], r.Regs[1], r.Regs[2], r.Regs[3])
	return l
}

// WriteWord writes the given word into the inferior's address space.
func WriteWord(t Trace, address uintptr, word uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], word)
	return t.Write(address, b[:])
}

// ReadWord reads the given word from the inferior's address space.
func ReadWord(t Trace, address uintptr) (uint64, error) {
	var b [8]byte
	if err := t.Read(address, b[:]); err != nil {
		return 0, err
	}
	var w uint64
	w = binary.LittleEndian.Uint64(b[:])
	return w, nil
}
