package kvm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
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

func TestGetRegs(t *testing.T) {
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
	type page [2 * 1048576]byte
	b := &page{}
	if err := v.mem([]byte(b[:]), 0); err != nil {
		t.Fatalf("creating %d byte region: got %v, want nil", len(b), err)
	}
	t.Logf("IP is %#x", r.Rip)
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
		t.Fatalf("New: got %v, want nil", err)
	}
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
	}

	defer v.Detach()
	if err := v.SingleStep(false); err != nil {
		t.Fatalf("Run: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	t.Logf("regs %s", showone("\t", r))
	r.Rip = 0x100000
	r.Rsp = 0x200000
	if true {
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
	for i := 0; i < 16; i++ {
		Debug = t.Logf
		if err := v.Run(); err != nil {
			t.Errorf("Run: got %v, want nil", err)
		}
		r, s, err := v.getRegs()
		if err != nil {
			t.Fatalf("getRegs: got %v, want nil", err)
		}
		e := v.cpu.VMRun.String()
		t.Logf("regs %s, exit %s", show("\t", r, s), e)
		if e != "ExitHalt" {
			t.Fatalf("VM exit: got %v, want 'ExitHalt', regs %s", e, showone("\t", r))
		}
	}
}

func TestDecode(t *testing.T) {
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
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

// This test no longer makes sense. It did for ptrace.
func testSegv(t *testing.T) {
	//1 0000 48A10000 	mov 0xff000000, %rax
	//1      00FF0000
	//1      0000
	segv := []byte{0x48, 0xa1, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00}
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
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
	//  ff 90 98 00 00 00       callq  *0x98(%rax)
	// nop hlt
	call := []byte{0xff, 0x90, 0x98, 0, 0, 0, 0x90, 0xf4}
	Debug = t.Logf
	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
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
	t.Logf("jmp target is %#x", v.regions[0].data[0x90:0x90+16])
	const initrax = 0x10000
	const bad = 0x10008
	// Put a pointer at initrax + 98
	copy(v.regions[0].data[initrax+0x98:], []byte{0xa0, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0xc3})
	r.Rax = initrax
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	Debug = t.Logf

	if err := v.Run(); err != nil {
		t.Errorf("Run: got %v, want nil", err)
	}

	ev := v.info
	t.Logf("Event %#x", ev)
	if ev.Trapno != ExitHlt {
		t.Errorf("Trapno: got %#x, want %#x", ev.Trapno, ExitHlt)
	}
	if ev.Addr != bad {
		t.Errorf("Addr: got %#x, want %#x", ev.Addr, bad)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	t.Logf("Rsp is %#x, regs %s", r.Rsp, show("After Call: ", r))
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
		t.Errorf("opcode: got %s, want 'HLT'", op)
	}
	t.Logf("Rip stopped at %#x, %#x", r.Rip, v.regions[0].data[r.Rip-1:r.Rip-1+8])
	t.Logf("Rsp is %#x, regs %s", r.Rsp, show("After Call: ", r))
	// Now for the fun. Try to resume it.
	// We should, then, see an ExitHlt
	// This actually doesn't work yet -- don't know how to make
	// it NOT take a reset
	if false {
		r.Rip += 6
		if err := v.SetRegs(r); err != nil {
			t.Fatalf("GetRegs: got %v, want nil", err)
		}
		rr, s, err := v.getRegs()
		if err != nil {
			t.Fatalf("GetRegs: got %v, want nil", err)
		}
		t.Logf("Try to resume the vm at %#x, regs now %s", r.Rip, show("resume: ", rr, s))

		if err := v.Run(); err != nil {
			t.Errorf("Run: got %v, want nil", err)
		}

		ev = v.info
		e = v.cpu.VMRun.String()
		t.Logf("Event %#x, %s", ev, e)
		if ev.Trapno != ExitHlt {
			t.Errorf("Trapno: got %#x, want %#x", ev.Trapno, ExitMmio)
		}
		rr, s, err = v.getRegs()
		if err != nil {
			t.Fatalf("GetRegs: got %v, want nil", err)
		}
		t.Logf(show("AFTER resume: ", rr, s))
	}
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
		t.Fatalf("New: got %v, want nil", err)
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

	if err := v.Run(); err != nil {
		t.Errorf("Run: got %v, want nil", err)
	}

	ev := v.info
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
		t.Fatalf("New: got %v, want nil", err)
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
	// bogus params to see if we can manages a segv
	r.Rcx = uint64(imageHandle)
	r.Rdx = uint64(systemTable)

	if err := v.Write(startpc, call); err != nil {
		t.Fatalf("Write(%#x, %#x): got %v, want nil", startpc, len(call), err)
	}
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}

	if err := v.Run(); err != nil {
		t.Errorf("Run: got %v, want nil", err)
	}

	ev := v.info
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
		t.Fatalf("New: got %v, want nil", err)
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

func TestTSC(t *testing.T) {
	//1 0000 0F31                  rdtsc
	//2 0002 F4                    hlt
	var tsc = []byte{0x0f, 0x31, 0xf4}

	v, err := New()
	if err != nil {
		t.Fatalf("New: got %v, want nil", err)
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
	const pc, sp = startpc + 3, startsp
	r.Rip = startpc
	r.Rsp = startsp

	if err := v.Write(startpc, tsc); err != nil {
		t.Fatalf("Write(%#x, %#x): got %v, want nil", startpc, len(tsc), err)
	}
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}

	if err := v.Run(); err != nil {
		t.Errorf("Run: got %v, want nil", err)
	}

	ev := v.info
	if ev.Trapno != ExitHlt {
		t.Errorf("Trapno: got %#x, want %v", ev.Trapno, ExitHlt)
	}
	if ev.Call_addr != pc {
		t.Errorf("Addr: got %#x, want %#x", ev.Call_addr, pc)
	}
	e := v.cpu.VMRun.String()
	if e != "ExitHalt" {
		t.Errorf("VM exit: got %v, want 'ExitHalt'", e)
	}
	_, r, g, err := v.Inst()
	if err != nil {
		t.Fatalf("Inst: got %v, want nil", err)
	}
	if !strings.Contains(g, "hlt") {
		t.Errorf("Inst: got %s, want call", g)
	}

}

// these are REALLY unpacked.
// intel vmx and amd svm are crazily similar and different, and I've learned the hard way, just keep things unpacked and it's
// easier to find out what's gone wrong ...
func TestSimple(t *testing.T) {
	mem_size := uintptr(0x200000)

	sys_fd, err := syscall.Open("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}

	api_ver, err := tioctl(sys_fd, kvmversion, 0)
	if err != nil {
		t.Fatal(err)
	}

	if api_ver != 12 {
		t.Fatalf("Got KVM api version %d, expected %d\n", api_ver, 12)
	}

	fd, err := tioctl(sys_fd, vmcreate, 0)
	if err != nil {
		t.Fatal(err)
	}

	vcpufd, err := tioctl(fd, createCPU, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tioctl(fd, setTSSAddr, 0xfffbd000); err != nil {
		t.Fatal(err)
	}

	mem, err := mmap(0, mem_size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE, -1, 0)
	if err != nil {
		t.Fatal(err)
	}

	//	madvise(mem, mem_size, MADV_MERGEABLE)
	for i := range mem {
		mem[i] = 0xf4
	}

	p := &bytes.Buffer{}
	u := &UserRegion{Slot: 0, Flags: 0, GPA: 0, Size: uint64(mem_size), UserAddr: uint64(uintptr(unsafe.Pointer(&mem[0])))}
	if err := binary.Write(p, binary.LittleEndian, u); err != nil {
		t.Fatal(err)
	}
	if false {
		log.Printf("ioctl %s", hex.Dump(p.Bytes()))
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(setMem), uintptr(unsafe.Pointer(&p.Bytes()[0]))); errno != 0 {
		t.Fatal(errno)
	}

	vcpu_mmap_size, err := tioctl(sys_fd, vcpuMmapSize, 0)
	if err != nil {
		t.Fatal(err)
	}

	kvm_run, err := mmap(0, uintptr(vcpu_mmap_size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, vcpufd, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Testing 64-bit mode\n")
	var rdata [unsafe.Sizeof(regs{})]byte
	var sdata [unsafe.Sizeof(sregs{})]byte
	r := &regs{}
	s := &sregs{}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), getRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
		t.Fatal(errno)
	}
	if err := binary.Read(bytes.NewReader(rdata[:]), binary.LittleEndian, r); err != nil {
		t.Fatal(err)
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), getSregs, uintptr(unsafe.Pointer(&sdata[0]))); errno != 0 {
		t.Fatal(errno)
	}
	if err := binary.Read(bytes.NewReader(sdata[:]), binary.LittleEndian, s); err != nil {
		t.Fatal(err)
	}

	//setup_long_mode(vm, &sregs, sabotage == 1)
	pml4 := 0x2000

	pdpt := 0x3000
	pd := 0x4000

	binary.LittleEndian.PutUint64(mem[pml4:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|pdpt))
	binary.LittleEndian.PutUint64(mem[pdpt:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|pd))
	binary.LittleEndian.PutUint64(mem[pd:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|PDE64_PS))
	//	if sabotage == 1 {
	//		fprintf(stderr, "SABOTAGING 2M PAGES FOR GIG PAGES\n")
	//		mem[pdpt0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS
	//	}

	s.CR3 = uint64(pml4)
	s.CR4 = CR4_PAE
	s.CR0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG
	s.EFER = EFER_LME | EFER_LMA

	//setup_64bit_code_segment(sregs)

	seg := segment{
		Base:     0,
		Limit:    0xffffffff,
		Selector: 1 << 3,
		Present:  1,
		Stype:    11, /* Code: execute, read, accessed */
		DPL:      0,
		DB:       0,
		S:        1, /* Code/data */
		L:        1,
		G:        1, /* 4KB granularity */
		AVL:      0,
	}

	s.CS = seg

	seg.Stype = 3 /* Data: read/write, accessed */
	seg.Selector = 2 << 3
	s.DS, s.ES, s.FS, s.GS, s.SS = seg, seg, seg, seg, seg

	var sw = &bytes.Buffer{}
	if err := binary.Write(sw, binary.LittleEndian, s); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setSregs, uintptr(unsafe.Pointer(&sw.Bytes()[0]))); errno != 0 {
		t.Fatal(errno)
	}

	/* Clear all FLAGS bits, except bit 1 which is always set. */
	r.Rflags = 2
	r.Rip = 0
	/* Create stack at top of 2 MB page and grow down. */
	r.Rsp = 2 << 20

	if err := binary.Write(bytes.NewBuffer(rdata[:]), binary.LittleEndian, r); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
		t.Fatal(errno)
	}

	//copy(mem[:], guest64[:])
	//return run_vm(vm, vcpu, 8)

	var vmrun VMRun
	if _, err := tioctl(vcpufd, run, 0); err != nil {

		t.Fatalf("run: %v", err)
	}
	vmr := bytes.NewBuffer(kvm_run)
	//Debug("vmr len %d", vmr.Len())
	if err := binary.Read(vmr, binary.LittleEndian, &vmrun); err != nil {
		t.Fatal(err)
	}

	switch vmrun.ExitReason {
	case ExitHlt:
		t.Logf("EXITHLT!\n")
		break
	default:
		t.Fatalf("Got exit_reason %d,expected KVM_EXIT_HLT (%d)\n", vmrun.ExitReason, ExitHlt)

	}

}

func TestSimple3Regions(t *testing.T) {
	mem_size := uintptr(0x2000_0000)

	sys_fd, err := syscall.Open("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}

	api_ver, err := tioctl(sys_fd, kvmversion, 0)
	if err != nil {
		t.Fatal(err)
	}

	if api_ver != 12 {
		t.Fatalf("Got KVM api version %d, expected %d\n", api_ver, 12)
	}

	fd, err := tioctl(sys_fd, vmcreate, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tioctl(fd, setTSSAddr, 0xfffbd000); err != nil {
		t.Fatal(err)
	}

	var regions = []struct {
		base uintptr
		size uintptr
		dat  []byte
	}{
		{base: 0, size: mem_size},
		{base: 0xffff0000, size: 0x10000},
		{base: 0xff000000, size: 0x800000},
	}
	for i, s := range regions {
		mem, err := mmap(s.base, s.size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE, -1, 0)
		if err != nil {
			t.Fatal(err)
		}

		for i := range mem {
			mem[i] = 0xf4
		}

		p := &bytes.Buffer{}
		u := &UserRegion{Slot: uint32(i), Flags: 0, GPA: uint64(s.base), Size: uint64(s.size), UserAddr: uint64(uintptr(unsafe.Pointer(&mem[0])))}
		if err := binary.Write(p, binary.LittleEndian, u); err != nil {
			t.Fatal(err)
		}
		if false {
			log.Printf("ioctl %s", hex.Dump(p.Bytes()))
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(setMem), uintptr(unsafe.Pointer(&p.Bytes()[0]))); errno != 0 {
			t.Fatal(errno)
		}
		regions[i].dat = mem
	}

	//	mem := regions[0].dat
	vcpufd, err := tioctl(fd, createCPU, 0)
	if err != nil {
		t.Fatal(err)
	}

	vcpu_mmap_size, err := tioctl(sys_fd, vcpuMmapSize, 0)
	if err != nil {
		t.Fatal(err)
	}

	kvm_run, err := mmap(0, uintptr(vcpu_mmap_size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, vcpufd, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Testing 64-bit mode\n")
	var rdata [unsafe.Sizeof(regs{})]byte
	var sdata [unsafe.Sizeof(sregs{})]byte
	r := &regs{}
	s := &sregs{}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), getRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
		t.Fatal(errno)
	}
	if err := binary.Read(bytes.NewReader(rdata[:]), binary.LittleEndian, r); err != nil {
		t.Fatal(err)
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), getSregs, uintptr(unsafe.Pointer(&sdata[0]))); errno != 0 {
		t.Fatal(errno)
	}
	if err := binary.Read(bytes.NewReader(sdata[:]), binary.LittleEndian, s); err != nil {
		t.Fatal(err)
	}

	//setup_long_mode(vm, &sregs, sabotage == 1)
	// page tables start at 0xffff0000
	// Just address the first 2m.
	pt := regions[1].dat
	pml4 := 0
	pdpt := 0x1000
	pd := 0x2000

	binary.LittleEndian.PutUint64(pt[pml4:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|pdpt|0xffff0000))
	binary.LittleEndian.PutUint64(pt[pdpt:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|pd|0xffff0000))
	binary.LittleEndian.PutUint64(pt[pd:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|PDE64_PS))
	//	if sabotage == 1 {
	//		fprintf(stderr, "SABOTAGING 2M PAGES FOR GIG PAGES\n")
	//		mem[pdpt0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS
	//	}

	s.CR3 = uint64(pml4 | 0xffff0000)
	s.CR4 = CR4_PAE
	s.CR0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG
	s.EFER = EFER_LME | EFER_LMA

	//setup_64bit_code_segment(sregs)

	seg := segment{
		Base:     0,
		Limit:    0xffffffff,
		Selector: 1 << 3,
		Present:  1,
		Stype:    11, /* Code: execute, read, accessed */
		DPL:      0,
		DB:       0,
		S:        1, /* Code/data */
		L:        1,
		G:        1, /* 4KB granularity */
		AVL:      0,
	}

	s.CS = seg

	seg.Stype = 3 /* Data: read/write, accessed */
	seg.Selector = 2 << 3
	s.DS, s.ES, s.FS, s.GS, s.SS = seg, seg, seg, seg, seg

	var sw = &bytes.Buffer{}
	if err := binary.Write(sw, binary.LittleEndian, s); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setSregs, uintptr(unsafe.Pointer(&sw.Bytes()[0]))); errno != 0 {
		t.Fatal(errno)
	}

	/* Clear all FLAGS bits, except bit 1 which is always set. */
	r.Rflags = 2
	r.Rip = 0
	/* Create stack at top of 2 MB page and grow down. */
	r.Rsp = 2 << 20

	if err := binary.Write(bytes.NewBuffer(rdata[:]), binary.LittleEndian, r); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
		t.Fatal(errno)
	}

	//copy(mem[:], guest64[:])
	//return run_vm(vm, vcpu, 8)

	var vmrun VMRun
	if _, err := tioctl(vcpufd, run, 0); err != nil {

		t.Fatalf("run: %v", err)
	}
	vmr := bytes.NewBuffer(kvm_run)
	//Debug("vmr len %d", vmr.Len())
	if err := binary.Read(vmr, binary.LittleEndian, &vmrun); err != nil {
		t.Fatal(err)
	}

	switch vmrun.ExitReason {
	case ExitHlt:
		t.Logf("EXITHLT!\n")
		break
	default:
		t.Fatalf("Got exit_reason %d,expected KVM_EXIT_HLT (%d)\n", vmrun.ExitReason, ExitHlt)

	}

}

func TestSimple3RegionsGetCPUID(t *testing.T) {
	mem_size := uintptr(0x2000_0000)

	sys_fd, err := syscall.Open("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}

	api_ver, err := tioctl(sys_fd, kvmversion, 0)
	if err != nil {
		t.Fatal(err)
	}

	if api_ver != 12 {
		t.Fatalf("Got KVM api version %d, expected %d\n", api_ver, 12)
	}

	fd, err := tioctl(sys_fd, vmcreate, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tioctl(fd, setTSSAddr, 0xfffbd000); err != nil {
		t.Fatal(err)
	}

	var regions = []struct {
		base uintptr
		size uintptr
		dat  []byte
	}{
		{base: 0, size: mem_size},
		{base: 0xffff0000, size: 0x10000},
		{base: 0xff000000, size: 0x800000},
	}
	for i, s := range regions {
		mem, err := mmap(s.base, s.size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE, -1, 0)
		if err != nil {
			t.Fatal(err)
		}

		for i := range mem {
			mem[i] = 0xf4
		}

		p := &bytes.Buffer{}
		u := &UserRegion{Slot: uint32(i), Flags: 0, GPA: uint64(s.base), Size: uint64(s.size), UserAddr: uint64(uintptr(unsafe.Pointer(&mem[0])))}
		if err := binary.Write(p, binary.LittleEndian, u); err != nil {
			t.Fatal(err)
		}
		if false {
			log.Printf("ioctl %s", hex.Dump(p.Bytes()))
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(setMem), uintptr(unsafe.Pointer(&p.Bytes()[0]))); errno != 0 {
			t.Fatal(errno)
		}
		regions[i].dat = mem
	}
	// Now for CPUID. What a pain.
	var i = &CPUIDInfo{
		nent: uint32(len(CPUIDInfo{}.ents)),
	}
	t.Logf("Check CPUID entries")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sys_fd), getCPUID, uintptr(unsafe.Pointer(i))); errno != 0 {
		t.Fatalf("Check CPUID entries err %v", errno)
	}
	t.Logf("%v", i)

	//	mem := regions[0].dat
	// This is exactly following the TestHalt failing test, if that matters to you.
	vcpufd, err := tioctl(fd, createCPU, 0)
	if err != nil {
		t.Fatal(err)
	}

	vcpu_mmap_size, err := tioctl(sys_fd, vcpuMmapSize, 0)
	if err != nil {
		t.Fatal(err)
	}

	kvm_run, err := mmap(0, uintptr(vcpu_mmap_size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, vcpufd, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Enable Debug
	var debug [unsafe.Sizeof(DebugControl{})]byte
	debug[0] = Enable | SingleStep
	debug[2] = 0x0002 // 0000
	if _, err := tioctl(vcpufd, setGuestDebug, uintptr(unsafe.Pointer(&debug[0]))); err != nil {
		t.Fatalf("Setting guest debug")
	}

	t.Logf("Testing 64-bit mode\n")
	var rdata [unsafe.Sizeof(regs{})]byte
	var sdata [unsafe.Sizeof(sregs{})]byte
	r := &regs{}
	s := &sregs{}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), getRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
		t.Fatal(errno)
	}
	if err := binary.Read(bytes.NewReader(rdata[:]), binary.LittleEndian, r); err != nil {
		t.Fatal(err)
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), getSregs, uintptr(unsafe.Pointer(&sdata[0]))); errno != 0 {
		t.Fatal(errno)
	}
	if err := binary.Read(bytes.NewReader(sdata[:]), binary.LittleEndian, s); err != nil {
		t.Fatal(err)
	}

	//setup_long_mode(vm, &sregs, sabotage == 1)
	// page tables start at 0xffff0000
	// Just address the first 2m.
	pt := regions[1].dat
	pml4 := 0
	pdpt := 0x1000
	pd := 0x2000

	binary.LittleEndian.PutUint64(pt[pml4:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|pdpt|0xffff0000))
	binary.LittleEndian.PutUint64(pt[pdpt:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|pd|0xffff0000))
	binary.LittleEndian.PutUint64(pt[pd:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|PDE64_PS))
	//	if sabotage == 1 {
	//		fprintf(stderr, "SABOTAGING 2M PAGES FOR GIG PAGES\n")
	//		mem[pdpt0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS
	//	}

	s.CR3 = uint64(pml4 | 0xffff0000)
	s.CR4 = CR4_PAE
	s.CR0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG
	s.EFER = EFER_LME | EFER_LMA

	//setup_64bit_code_segment(sregs)

	seg := segment{
		Base:     0,
		Limit:    0xffffffff,
		Selector: 1 << 3,
		Present:  1,
		Stype:    11, /* Code: execute, read, accessed */
		DPL:      0,
		DB:       0,
		S:        1, /* Code/data */
		L:        1,
		G:        1, /* 4KB granularity */
		AVL:      0,
	}

	s.CS = seg

	seg.Stype = 3 /* Data: read/write, accessed */
	seg.Selector = 2 << 3
	s.DS, s.ES, s.FS, s.GS, s.SS = seg, seg, seg, seg, seg

	/* Clear all FLAGS bits, except bit 1 which is always set. */
	r.Rflags = 2
	r.Rip = 0
	/* Create stack at top of 2 MB page and grow down. */
	r.Rsp = 2 << 20

	if err := binary.Write(bytes.NewBuffer(rdata[:]), binary.LittleEndian, r); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
		t.Fatal(errno)
	}

	var sw = &bytes.Buffer{}
	if err := binary.Write(sw, binary.LittleEndian, s); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setSregs, uintptr(unsafe.Pointer(&sw.Bytes()[0]))); errno != 0 {
		t.Fatal(errno)
	}

	//copy(mem[:], guest64[:])
	//return run_vm(vm, vcpu, 8)

	var vmrun VMRun
	if _, err := tioctl(vcpufd, run, 0); err != nil {

		t.Fatalf("run: %v", err)
	}
	vmr := bytes.NewBuffer(kvm_run)
	//Debug("vmr len %d", vmr.Len())
	if err := binary.Read(vmr, binary.LittleEndian, &vmrun); err != nil {
		t.Fatal(err)
	}

	switch vmrun.ExitReason {
	case ExitHlt:
		t.Logf("EXITHLT!\n")
		break
	default:
		t.Fatalf("Got exit_reason %d,expected KVM_EXIT_HLT (%d)\n", vmrun.ExitReason, ExitHlt)

	}

}

func TestSimple3RegionsGetSetCPUID(t *testing.T) {
	mem_size := uintptr(0x8000_0000)

	sys_fd, err := syscall.Open("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}

	api_ver, err := tioctl(sys_fd, kvmversion, 0)
	if err != nil {
		t.Fatal(err)
	}

	if api_ver != 12 {
		t.Fatalf("Got KVM api version %d, expected %d\n", api_ver, 12)
	}

	fd, err := tioctl(sys_fd, vmcreate, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tioctl(fd, setTSSAddr, 0xfffbd000); err != nil {
		t.Fatal(err)
	}

	// This is exactly following the TestHalt failing test, if that matters to you.
	vcpufd, err := tioctl(fd, createCPU, 0)
	if err != nil {
		t.Fatal(err)
	}

	vcpu_mmap_size, err := tioctl(sys_fd, vcpuMmapSize, 0)
	if err != nil {
		t.Fatal(err)
	}

	kvm_run, err := mmap(0, uintptr(vcpu_mmap_size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, vcpufd, 0)
	if err != nil {
		t.Fatal(err)
	}

	var regions = []struct {
		base uintptr
		size uintptr
		dat  []byte
	}{
		{base: 0, size: mem_size},
		{base: 0xffff0000, size: 0x10000},
		{base: 0xff000000, size: 0x800000},
	}
	for i, s := range regions {
		mem, err := mmap(s.base, s.size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE, -1, 0)
		if err != nil {
			t.Fatal(err)
		}

		for i := range mem {
			mem[i] = 0xf4
		}

		p := &bytes.Buffer{}
		u := &UserRegion{Slot: uint32(i), Flags: 0, GPA: uint64(s.base), Size: uint64(s.size), UserAddr: uint64(uintptr(unsafe.Pointer(&mem[0])))}
		if err := binary.Write(p, binary.LittleEndian, u); err != nil {
			t.Fatal(err)
		}
		if false {
			log.Printf("ioctl %s", hex.Dump(p.Bytes()))
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(setMem), uintptr(unsafe.Pointer(&p.Bytes()[0]))); errno != 0 {
			t.Fatal(errno)
		}
		regions[i].dat = mem
	}
	// Now for CPUID. What a pain.
	var i = &CPUIDInfo{
		nent: uint32(len(CPUIDInfo{}.ents)),
	}
	t.Logf("Check CPUID entries")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(sys_fd), getCPUID, uintptr(unsafe.Pointer(i))); errno != 0 {
		t.Fatalf("Check CPUID entries err %v", errno)
	}
	t.Logf("%v", i)

	//	mem := regions[0].dat
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setCPUID, uintptr(unsafe.Pointer(i))); errno != 0 {
		t.Fatalf("Set  CPUID entries err %v", errno)
	}

	// Enable Debug
	var debug [unsafe.Sizeof(DebugControl{})]byte
	debug[0] = Enable | SingleStep
	debug[2] = 0x0002 // 0000
	if _, err := tioctl(vcpufd, setGuestDebug, uintptr(unsafe.Pointer(&debug[0]))); err != nil {
		t.Fatalf("Setting guest debug")
	}

	t.Logf("Testing 64-bit mode\n")
	var rdata [unsafe.Sizeof(regs{})]byte
	var sdata [unsafe.Sizeof(sregs{})]byte
	r := &regs{}
	s := &sregs{}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), getRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
		t.Fatal(errno)
	}
	if err := binary.Read(bytes.NewReader(rdata[:]), binary.LittleEndian, r); err != nil {
		t.Fatal(err)
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), getSregs, uintptr(unsafe.Pointer(&sdata[0]))); errno != 0 {
		t.Fatal(errno)
	}
	if err := binary.Read(bytes.NewReader(sdata[:]), binary.LittleEndian, s); err != nil {
		t.Fatal(err)
	}

	//setup_long_mode(vm, &sregs, sabotage == 1)
	// page tables start at 0xffff0000
	// Just address the first 2m.
	pt := regions[1].dat
	pml4 := 0
	pdpt := 0x1000
	pd := 0x2000

	binary.LittleEndian.PutUint64(pt[pml4:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|pdpt|0xffff0000))
	binary.LittleEndian.PutUint64(pt[pdpt:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|pd|0xffff0000))
	binary.LittleEndian.PutUint64(pt[pd:], uint64(PDE64_PRESENT|PDE64_RW|PDE64_USER|PDE64_PS))
	//	if sabotage == 1 {
	//		fprintf(stderr, "SABOTAGING 2M PAGES FOR GIG PAGES\n")
	//		mem[pdpt0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS
	//	}

	s.CR3 = uint64(pml4 | 0xffff0000)
	s.CR4 = CR4_PAE
	s.CR0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG
	s.EFER = EFER_LME | EFER_LMA

	//setup_64bit_code_segment(sregs)

	seg := segment{
		Base:     0,
		Limit:    0xffffffff,
		Selector: 1 << 3,
		Present:  1,
		Stype:    11, /* Code: execute, read, accessed */
		DPL:      0,
		DB:       0,
		S:        1, /* Code/data */
		L:        1,
		G:        1, /* 4KB granularity */
		AVL:      0,
	}

	s.CS = seg

	seg.Stype = 3 /* Data: read/write, accessed */
	seg.Selector = 2 << 3
	s.DS, s.ES, s.FS, s.GS, s.SS = seg, seg, seg, seg, seg

	/* Clear all FLAGS bits, except bit 1 which is always set. */
	r.Rflags = 2
	r.Rip = 0
	/* Create stack at top of 2 MB page and grow down. */
	r.Rsp = 2 << 20

	if err := binary.Write(bytes.NewBuffer(rdata[:]), binary.LittleEndian, r); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setRegs, uintptr(unsafe.Pointer(&rdata[0]))); errno != 0 {
		t.Fatal(errno)
	}

	var sw = &bytes.Buffer{}
	if err := binary.Write(sw, binary.LittleEndian, s); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(vcpufd), setSregs, uintptr(unsafe.Pointer(&sw.Bytes()[0]))); errno != 0 {
		t.Fatal(errno)
	}

	//copy(mem[:], guest64[:])
	//return run_vm(vm, vcpu, 8)

	var vmrun VMRun
	if _, err := tioctl(vcpufd, run, 0); err != nil {

		t.Fatalf("run: %v", err)
	}
	vmr := bytes.NewBuffer(kvm_run)
	//Debug("vmr len %d", vmr.Len())
	if err := binary.Read(vmr, binary.LittleEndian, &vmrun); err != nil {
		t.Fatal(err)
	}

	switch vmrun.ExitReason {
	case ExitHlt:
		t.Logf("EXITHLT!\n")
		break
	default:
		t.Fatalf("Got exit_reason %d,expected KVM_EXIT_HLT (%d)\n", vmrun.ExitReason, ExitHlt)

	}

}

func TestSimpleUsePackage(t *testing.T) {

	// This is New()
	k, err := os.OpenFile(*deviceName, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v := version(k); v != APIVersion {
		t.Fatal("Wrong version")
	}

	vm, err := startvm(k)
	if err != nil {
		t.Fatal(err)
	}

	tr := &Tracee{
		dev: k,
		vm:  vm,
	}

	if err := tr.archInit(); err != nil {
		t.Fatal(err)
	}

	// if false { // Enable Debug
	// 	var debug [unsafe.Sizeof(DebugControl{})]byte
	// 	debug[0] = Enable | SingleStep
	// 	debug[2] = 0x0002 // 0000
	// 	if _, err := tioctl(vcpufd, setGuestDebug, uintptr(unsafe.Pointer(&debug[0]))); err != nil {
	// 		t.Fatalf("Setting guest debug")
	// 	}
	// }

	var vmrun VMRun
	if _, err := tioctl(int(tr.cpu.fd), run, 0); err != nil {

		t.Fatalf("run: %v", err)
	}
	vmr := bytes.NewBuffer(tr.cpu.m)
	//Debug("vmr len %d", vmr.Len())
	if err := binary.Read(vmr, binary.LittleEndian, &vmrun); err != nil {
		t.Fatal(err)
	}

	switch vmrun.ExitReason {
	case ExitHlt:
		t.Logf("EXITHLT!\n")
		break
	default:
		t.Fatalf("Got exit_reason %d,expected KVM_EXIT_HLT (%d)\n", vmrun.ExitReason, ExitHlt)

	}

}
