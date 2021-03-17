package kvm

import (
	"fmt"
	"io"
	"syscall"

	"golang.org/x/arch/x86/x86asm"
)

// Should we ever want to also have ptrace back (unlikely)
// these functions should be changed to operate on an
// interface. For now, let's just get this done.

// Params sets paramers in %rcx, %rdx
func (p *Tracee) Params(ImageHandle, SystemTable uintptr) error {
	r, err := p.GetRegs()
	if err != nil {
		return err
	}
	r.Rcx = uint64(ImageHandle)
	r.Rdx = uint64(SystemTable)
	return p.SetRegs(r)
}

// Inst retrieves an instruction from the traced process.
// It gets messy if the Rip is in unaddressable space; that means we
// must fetch the saved Rip from [Rsp].
func (t *Tracee) Inst() (*x86asm.Inst, *syscall.PtraceRegs, error) {
	r, err := t.GetRegs()
	if err != nil {
		return nil, nil, fmt.Errorf("Inst:Getregs:%v", err)
	}
	pc := r.Rip
	sp := r.Rsp
	Debug("Inst: pc %#x, sp %#x", pc, sp)
	// We maintain all the function pointers in non-addressable space for now.
	// It is in the classic BIOS space.
	if r.Rip > 0xff000000 {
		cpc, err := t.ReadWord(uintptr(sp))
		if err != nil {
			return nil, nil, fmt.Errorf("Inst:ReadWord at %#x::%v", sp, err)
		}
		Debug("cpc is %#x from sp", cpc)
		// what a hack.
		if cpc == 0x100000 {
			return nil, nil, io.EOF
		}
		var call [5]byte
		if err := t.Read(uintptr(cpc-5), call[:]); err != nil {
			return nil, nil, fmt.Errorf("Can' read PC at #%x, err %v", pc, err)
		}

		// It's simple, if call[0] is 0xff, it's 5 bytes, else if call[2] is 0xff, it's 3,
		// else we're screwed.
		switch {
		case call[0] == 0xff:
			cpc -= 5
		case call[2] == 0xff:
			cpc -= 3
		case call[3] == 0xff:
			cpc -= 2
		default:
			return nil, nil, fmt.Errorf("Can't interpret call @ %#x: %#x", cpc-5, call)
		}
		pc = cpc
	}
	// We know the PC; grab a bunch of bytes there, then decode and print
	insn := make([]byte, 16)
	if err := t.Read(uintptr(pc), insn); err != nil {
		return nil, nil, fmt.Errorf("Can' read PC at #%x, err %v", pc, err)
	}
	d, err := x86asm.Decode(insn, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("Can't decode %#02x: %v", insn, err)
	}
	return &d, r, nil
}

// Disasm returns a string for the disassembled instruction.
func Disasm(t *Tracee) (string, error) {
	d, r, err := t.Inst()
	if err != nil {
		return "", fmt.Errorf("Can't decode %#02x: %v", d, err)
	}
	return x86asm.GNUSyntax(*d, uint64(r.Rip), nil), nil
}

// Asm returns a string for the given instruction at the given pc
func Asm(d *x86asm.Inst, pc uint64) string {
	return "\"" + x86asm.GNUSyntax(*d, pc, nil) + "\""
}
