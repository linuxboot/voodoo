package kvm

import (
	"testing"
)

func TestNew(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	t.Logf("%v", v)
}

func TestOpenDetach(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	t.Logf("%v", v)
	err = v.Exec("", []string{""}...)
	if err := v.Detach(); err != nil {
		t.Fatalf("Detach: Got %v, want nil", err)
	}
}

func TestCreateRegion(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	type page [2 * 1048576]byte
	b := &page{}
	if err := v.mem([]byte(b[:]), 0); err != nil {
		t.Fatalf("creating %d byte region: got %v, want nil", len(b), err)
	}
}

func TestCreateCpu(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.createCPU(0); err != nil {
		t.Fatalf("createCPU: got %v, want nil", err)
	}
}

func TestGetRegs(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	t.Logf("%v", v)
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	t.Logf("Regs %v", r)
}
