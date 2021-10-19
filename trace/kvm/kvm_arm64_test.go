package kvm

import (
	"fmt"
	"syscall"
	"testing"

	"golang.org/x/arch/arm/armasm"
)

// this is a simple decoder to get around a circular dependency.
// bad design?
// Inst retrieves an instruction from the traced process.
// It gets messy if the Rip is in unaddressable space; that means we
// must fetch the saved Rip from [Rsp].
func (t *Tracee) Inst() (*armasm.Inst, *syscall.PtraceRegs, string, error) {
	r, err := t.GetRegs()
	if err != nil {
		return nil, nil, "", fmt.Errorf("Inst:Getregs:%v", err)
	}
	pc := r.Pc
	insn := make([]byte, 16)
	if err := t.Read(uintptr(pc), insn); err != nil {
		return nil, nil, "", fmt.Errorf("Can' read PC at #%x, err %v", pc, err)
	}
	d, err := armasm.Decode(insn, 64)
	if err != nil {
		return nil, nil, "", fmt.Errorf("Can't decode %#02x: %v", insn, err)
	}
	return &d, r, armasm.GNUSyntax(d), nil
}

func TestNew(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
	}
	t.Logf("%v", v)
}
