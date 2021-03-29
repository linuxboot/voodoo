package kvm

import (
	"fmt"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// this is a simple decoder to get around a circular dependency.
// bad design?
// Inst retrieves an instruction from the traced process.
// It gets messy if the Rip is in unaddressable space; that means we
// must fetch the saved Rip from [Rsp].
func (t *Tracee) Inst() (*x86asm.Inst, *syscall.PtraceRegs, string, error) {
	r, err := t.GetRegs()
	if err != nil {
		return nil, nil, "", fmt.Errorf("Inst:Getregs:%v", err)
	}
	pc := r.Rip
	insn := make([]byte, 16)
	if err := t.Read(uintptr(pc), insn); err != nil {
		return nil, nil, "", fmt.Errorf("Can' read PC at #%x, err %v", pc, err)
	}
	d, err := x86asm.Decode(insn, 64)
	if err != nil {
		return nil, nil, "", fmt.Errorf("Can't decode %#02x: %v", insn, err)
	}
	return &d, r, x86asm.GNUSyntax(d, uint64(r.Rip), nil), nil
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

func TestReadWrite(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
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
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
	}
}

func TestGetRegs(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
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
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
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
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
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
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
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
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
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
	i, r, _, err := v.Inst()
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
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
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
	i, r, _, err := v.Inst()
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
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
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
	if ev.Trapno != ExitMmio {
		t.Errorf("Trapno: got %#x, want %#x", ev.Trapno, ExitMmio)
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
	i, r, _, err := v.Inst()
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

func TestPush(t *testing.T) {
	//5 000f 55       	push %rbp
	//6      48 89 e5       mov    %rsp,%rbp
	//9 0010 59       	pop %rcx
	//a 0011 F4       	hlt
	call := []byte{0x55, 0x48, 0x89, 0xe5, 0x59, 0xf4}
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
	}
	if err := v.SingleStep(false); err != nil {
		t.Fatalf("Run: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}

	const rbp, startpc, startsp = 0x3afef00dd00dfeed, 0x70941000, 0x80000
	const pc, sp = startpc + 6, startsp
	r.Rbp = rbp
	r.Rip = startpc
	r.Rsp = startsp

	if err := v.Write(startpc, call); err != nil {
		t.Fatalf("Write(%#x, %#x): got %v, want nil", startpc, len(call), err)
	}
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
	if ev.Trapno != ExitHlt {
		t.Errorf("Trapno: got %#x, want %v", ev.Trapno, ExitHlt)
	}
	if ev.Call_addr != pc {
		t.Errorf("Addr: got %#x, want %#x", ev.Addr, pc)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	e := v.cpu.VMRun.String()
	t.Logf("IP is %#x, exit %s", r.Rip, e)
	if e != "ExitHalt" {
		t.Errorf("VM exit: got %v, want 'ExitMHalt'", e)
	}
	i, r, _, err := v.Inst()
	t.Logf("Inst returns %v, %v, %v", i, r, err)
	if err != nil {
		t.Fatalf("Inst: got %v, want nil", err)
	}
	t.Logf("Rsp is %#x", r.Rsp)
	if r.Rsp != sp {
		t.Fatalf("SP: got %#x, want %#x", r.Rsp, sp)
	}
	check, err := v.ReadWord(sp - 8)
	if err != nil {
		t.Fatalf("Reading back word from SP@%#x: got %v, want nil", sp-8, err)
	}
	if check != rbp {
		t.Fatalf("Check from memory: got %#x, want %#x", check, rbp)
	}
	if rbp != r.Rcx {
		t.Fatalf("Check rcx: got %#x, want %#x", r.Rcx, rbp)
	}
	if r.Rbp != r.Rsp-8 {
		t.Fatalf("Check rbp: got %#x, want %#x", r.Rsp-8, r.Rbp)
	}
}

func TestCallEFI(t *testing.T) {
	// 1 0000 48A10000 	mov $0xff000000, %rax
	// 1      00FF0000
	// 1      0000
	// 3 000d FF10     	call *(%rax)
	call := []byte{0x48, 0xb8, 0x00, 0x00, 0x00, 0xef, 0x00, 0x00, 0x00, 0x00, 0xff, 0x10, 0xf4}
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
	}
	if err := v.SingleStep(false); err != nil {
		t.Fatalf("Run: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}

	const efi, startpc, startsp = 0xef000000, 0x70941000, 0x80000
	const pc, sp = startpc + 10, startsp - 8
	r.Rip = startpc
	r.Rsp = startsp

	if err := v.Write(startpc, call); err != nil {
		t.Fatalf("Write(%#x, %#x): got %v, want nil", startpc, len(call), err)
	}
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}

	go func() {
		if err := v.Run(); err != nil {
			t.Errorf("Run: got %v, want nil", err)
		}
	}()
	ev := <-v.Events()
	if ev.Trapno != ExitMmio {
		t.Errorf("Trapno: got %#x, want %v", ev.Trapno, ExitHlt)
	}
	if ev.Call_addr != pc {
		t.Errorf("Addr: got %#x, want %#x", ev.Call_addr, pc)
	}
	e := v.cpu.VMRun.String()
	if e != "ExitMmio" {
		t.Errorf("VM exit: got %v, want 'ExitMmio'", e)
	}
	_, r, g, err := v.Inst()
	if err != nil {
		t.Fatalf("Inst: got %v, want nil", err)
	}
	if !strings.Contains(g, "call") {
		t.Errorf("Inst: got %s, want call", g)
	}
}

func TestWriteWord(t *testing.T) {
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
	}
	if err := v.SingleStep(false); err != nil {
		t.Fatalf("Run: got %v, want nil", err)
	}
	const addr = 0x8086
	w := uint64(0x700ddeadfeedbeef)
	if err := v.WriteWord(addr, w); err != nil {
		t.Fatalf("Writing %#x at %#x: got %v, want nil", w, addr, err)
	}
	rw, err := v.ReadWord(addr)
	if err != nil {
		t.Fatalf("Reading %#x: got %v, want nil", addr, err)
	}
	if rw != w {
		t.Fatalf("Reading %#x: got %#x, want %#x", addr, rw, w)
	}
}
