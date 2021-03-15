package kvm

import (
	"syscall"
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
	if err := v.createCPU(0); err != nil {
		t.Fatalf("createCPU: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	t.Logf("Regs %v", r)
}

func TestSetRegs(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	t.Logf("%v", v)
	if err := v.createCPU(0); err != nil {
		t.Fatalf("createCPU: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	pr := &syscall.PtraceRegs{}
	pr.R15 = ^r.R15
	pr.R14 = ^r.R14
	pr.R13 = ^r.R13
	pr.R12 = ^r.R12
	pr.Rbp = ^r.Rbp
	pr.Rbx = ^r.Rbx
	pr.R11 = ^r.R11
	pr.R10 = ^r.R10
	pr.R9 = ^r.R9
	pr.R8 = ^r.R8
	pr.Rax = ^r.Rax
	pr.Rcx = ^r.Rcx
	pr.Rdx = ^r.Rdx
	pr.Rsi = ^r.Rsi
	pr.Rdi = ^r.Rdi
	pr.Rip = ^r.Rip
	pr.Rsp = ^r.Rsp
	if err := v.SetRegs(pr); err != nil {
		t.Fatalf("setregs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}

	diff(t.Errorf, pr.R15, r.R15, "R15")
	diff(t.Errorf, pr.R14, r.R14, "R14")
	diff(t.Errorf, pr.R13, r.R13, "R13")
	diff(t.Errorf, pr.R12, r.R12, "R12")
	diff(t.Errorf, pr.Rbp, r.Rbp, "Rbp")
	diff(t.Errorf, pr.Rbx, r.Rbx, "Rbx")
	diff(t.Errorf, pr.R11, r.R11, "R11")
	diff(t.Errorf, pr.R10, r.R10, "R10")
	diff(t.Errorf, pr.R9, r.R9, "R9")
	diff(t.Errorf, pr.R8, r.R8, "R8")
	diff(t.Errorf, pr.Rax, r.Rax, "Rax")
	diff(t.Errorf, pr.Rcx, r.Rcx, "Rcx")
	diff(t.Errorf, pr.Rdx, r.Rdx, "Rdx")
	diff(t.Errorf, pr.Rsi, r.Rsi, "Rsi")
	diff(t.Errorf, pr.Rdi, r.Rdi, "Rdi")
	diff(t.Errorf, pr.Rip, r.Rip, "Rip")
	diff(t.Errorf, pr.Rsp, r.Rsp, "Rsp")

}

func diff(f func(string, ...interface{}), a, b uint64, n string) bool {
	if a != b {
		f("%s: got %#x want %#x", n, a, b)
		return true
	}
	return false
}
