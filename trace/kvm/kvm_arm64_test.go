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

func TestNewDetach(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
	}
	t.Logf("%v", v)

	if err := v.Detach(); err != nil {
		t.Fatalf("Detach: Got %v, want nil", err)
	}
}

func TestCreateRegion(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
	}
	defer v.Detach()
	type page [2 * 1048576]byte
	b := &page{}
	if err := v.mem([]byte(b[:]), 0); err == nil {
		t.Fatalf("creating %d byte region: got nil, want 'file exists'", len(b))
	}
}

func TestReadWrite(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
	}
	defer v.Detach()
	const addr = uintptr(0x6000)
	page := make([]byte, 2*1048576)
	if err := v.Read(addr, page); err != nil {
		t.Fatalf("Read(%#x, %#x): got %v, want nil", addr, len(page), err)
	}

	for i := range page {
		page[i] = uint8(i)
	}
	if err := v.Write(addr, page); err != nil {
		t.Fatalf("Write(%#x, %#x): got %v, want nil", addr, len(page), err)
	}

	if err := v.Read(addr, page); err != nil {
		t.Fatalf("Read(%#x, %#x): got %v, want nil", addr, len(page), err)
	}
	var diff int
	for i := range page {
		if page[i] != uint8(i) {
			diff++
		}
	}
	if diff != 0 {
		t.Errorf("Reading back: got %d differences, want 0", diff)
	}
}

func TestCreateCpu(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
	}
}

func diff(f func(string, ...interface{}), a, b uint64, n string) bool {
	if a != b {
		f("%s: got %#x want %#x", n, a, b)
		return true
	}
	return false
}

func TestGetRegs(t *testing.T) {
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
	}
	defer v.Detach()
	t.Logf("%v", v)
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	pr, err := v.GetRegs()
	if err != nil {
		t.Fatalf("2nd GetRegs: got %v, want nil", err)
	}
	for i := range r.Regs {
		diff(t.Errorf, pr.Regs[i], r.Regs[i], fmt.Sprintf("R%d", i))
	}
}
