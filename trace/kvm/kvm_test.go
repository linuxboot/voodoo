package kvm

import (
	"fmt"
	"syscall"
	"testing"

	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

// this is a simple decoder to get around a circular dependency.
// bad design?
// Inst retrieves an instruction from the traced process.
// It gets messy if the Rip is in unaddressable space; that means we
// must fetch the saved Rip from [Rsp].
func (t *Tracee) Inst() (*x86asm.Inst, *syscall.PtraceRegs, error) {
	r, err := t.GetRegs()
	if err != nil {
		return nil, nil, fmt.Errorf("Inst:Getregs:%v", err)
	}
	pc := r.Rip
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
	if err := v.mem([]byte(b[:]), 0); err == nil {
		t.Fatalf("creating %d byte region: got nil, want 'file exists'", len(b))
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
	pr, err := v.GetRegs()
	if err != nil {
		t.Fatalf("2nd GetRegs: got %v, want nil", err)
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
	diff(t.Errorf, uint64(r.Cs), uint64(r.Cs), "cs")
	diff(t.Errorf, uint64(r.Ds), uint64(r.Ds), "cs")
	diff(t.Errorf, uint64(r.Ss), uint64(r.Ss), "cs")
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
	t.Logf(show("Read:\t", r))
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
	t.Logf(show("Set:\t", pr))
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	t.Logf("%s", show("After:\t", r))
	// Don't check 15-8 for now

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

func testRunUD2(t *testing.T) {
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
	type page [2 * 1048576]byte
	b := &page{}
	if err := v.mem([]byte(b[:]), 0); err != nil {
		t.Fatalf("creating %d byte region: got %v, want nil", len(b), err)
	}
	t.Logf("IP is %#x", r.Rip)
	go func() {
		for range v.Events() {
		}
		t.Logf("No more events")
	}()
	if err := v.Run(); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	t.Logf("IP is %#x", r.Rip)
}

func TestHalt(t *testing.T) {
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.createCPU(0); err != nil {
		t.Fatalf("createCPU: got %v, want nil", err)
	}
	if err := v.SingleStep(false); err != nil {
		t.Fatalf("Run: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	t.Logf("IP is %#x", r.Rip)
	if false {
		//r.Rip = 0
		//		r.Cs = 0
		if err := v.SetRegs(r); err != nil {
			t.Fatalf("setregs: got %v, want nil", err)
		}

		t.Logf(show("Set:\t", r))
		r, err = v.GetRegs()
		if err != nil {
			t.Fatalf("GetRegs: got %v, want nil", err)
		}
		t.Logf("IP is %#x", r.Rip)
	}
	go func() {
		for range v.Events() {
		}
		t.Logf("No more events")
	}()
	for i := 0; i < 16; i++ {
		Debug = t.Logf
		if err := v.Run(); err != nil {
			t.Errorf("Run: got %v, want nil", err)
		}
		r, err = v.GetRegs()
		if err != nil {
			t.Fatalf("GetRegs: got %v, want nil", err)
		}
		e := v.cpu.VMRun.String()
		t.Logf("IP is %#x, exit %s", r.Rip, e)
		if e != "ExitHalt" {
			t.Errorf("VM exit: got %v, want 'ExitHalt'", e)
		}
	}
}

func TestDecode(t *testing.T) {
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.createCPU(0); err != nil {
		t.Fatalf("createCPU: got %v, want nil", err)
	}
	if err := v.SingleStep(false); err != nil {
		t.Fatalf("Run: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	go func() {
		for range v.Events() {
		}
		t.Logf("No more events")
	}()

	Debug = t.Logf
	if err := v.Run(); err != nil {
		t.Errorf("Run: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	e := v.cpu.VMRun.String()
	t.Logf("IP is %#x, exit %s", r.Rip, e)
	if e != "ExitHalt" {
		t.Errorf("VM exit: got %v, want 'ExitHalt'", e)
	}
	i, r, err := v.Inst()
	t.Logf("Inst returns %v, %v, %v", i, r, err)
	if err != nil {
		t.Fatalf("Inst: got %v, want nil", err)
	}
	op := i.Op.String()
	if op != "HLT" {
		t.Fatalf("opcode: got %s, want HLT", op)
	}
}

func TestSegv(t *testing.T) {
	//1 0000 48A10000 	mov 0xff000000, %rax
	//1      00FF0000
	//1      0000
	segv := []byte{0x48, 0xa1, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00}
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.createCPU(0); err != nil {
		t.Fatalf("createCPU: got %v, want nil", err)
	}
	if err := v.SingleStep(false); err != nil {
		t.Fatalf("Run: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	r.Rip = 0x10000
	copy(v.regions[0].data[0x10000:], segv)
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	Debug = t.Logf
	go func() {
		for range v.Events() {
		}
		t.Logf("No more events")
	}()
	if err := v.Run(); err != nil {
		t.Errorf("Run: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	e := v.cpu.VMRun.String()
	t.Logf("IP is %#x, exit %s", r.Rip, e)
	if e != "ExitMmio" {
		t.Errorf("VM exit: got %v, want 'ExitMmio'", e)
	}
	i, r, err := v.Inst()
	t.Logf("Inst returns %v, %v, %v", i, r, err)
	if err != nil {
		t.Fatalf("Inst: got %v, want nil", err)
	}
	op := i.Op.String()
	if op != "MOV" {
		t.Fatalf("opcode: got %s, want 'MOV'", op)
	}
}

func TestCall(t *testing.T) {
	// 000d FF10     	call *(%rax)
	call := []byte{0xff, 0x10}
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.createCPU(0); err != nil {
		t.Fatalf("createCPU: got %v, want nil", err)
	}
	if err := v.SingleStep(false); err != nil {
		t.Fatalf("Run: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	copy(v.regions[0].data[0x10000:], call)

	r.Rip = 0x10000
	r.Rsp = 0x8000
	const bad = 0xffffff02
	r.Rax = bad
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	Debug = t.Logf

	go func() {
		if err := v.Run(); err != nil {
			t.Errorf("Run: got %v, want nil", err)
		}
	}()
	ev := <-v.Events()
	t.Logf("Event %#x", ev)
	if ev.Trapno != uint32(unix.SIGSEGV) {
		t.Errorf("Trapno: got %#x, want %#x", ev.Trapno, unix.SIGSEGV)
	}
	if ev.Addr != bad {
		t.Errorf("Addr: got %#x, want %#x", ev.Addr, bad)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	e := v.cpu.VMRun.String()
	t.Logf("IP is %#x, exit %s", r.Rip, e)
	if e != "ExitMmio" {
		t.Errorf("VM exit: got %v, want 'ExitMmio'", e)
	}
	i, r, err := v.Inst()
	t.Logf("Inst returns %v, %v, %v", i, r, err)
	if err != nil {
		t.Fatalf("Inst: got %v, want nil", err)
	}
	op := i.Op.String()
	if op != "CALL" {
		t.Fatalf("opcode: got %s, want 'CALL'", op)
	}
	t.Logf("Rsp is %#x", r.Rsp)
}
