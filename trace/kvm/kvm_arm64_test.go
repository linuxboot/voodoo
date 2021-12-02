package kvm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/sys/unix"
)

// this is a simple decoder to get around a circular dependency.
// bad design?
// Inst retrieves an instruction from the traced process.
// It gets messy if the Rip is in unaddressable space; that means we
// must fetch the saved Rip from [Rsp].
func (t *Tracee) Inst() (*arm64asm.Inst, *syscall.PtraceRegs, string, error) {
	var dc = []byte{
		0x7e, 0x0b, 0xd5, //  200048:	d50b7e26 	dc	civac, xxxx
	}
	r, err := t.GetRegs()
	if err != nil {
		return nil, nil, "", fmt.Errorf("Inst:Getregs:%v", err)
	}
	pc := r.Pc
	insn := make([]byte, 4)
	if err := t.Read(uintptr(pc), insn); err != nil {
		return nil, nil, "", fmt.Errorf("Can' read PC at #%x, err %v", pc, err)
	}
	if bytes.Equal(insn[1:], dc) {
		return &arm64asm.Inst{}, r, "dc civac, whatever", nil
	}
	d, err := arm64asm.Decode(insn)
	// There are some privileged opcodes we just can't do.
	if err != nil {
		return nil, r, fmt.Sprintf("%#02x@%#02x", insn, pc), fmt.Errorf("Can't decode %#02x@%#x: %v", pc, insn, err)
	}
	return &d, r, arm64asm.GNUSyntax(d), nil
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
	for i := range r.Regs {
		pr.Regs[i] = ^r.Regs[i]
	}
	if err := v.SetRegs(pr); err != nil {
		t.Fatalf("setregs: got %v, want nil", err)
	}
	t.Logf(show("Set:\t", pr))
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	t.Logf("%s", show("After:\t", r))
	for i := range r.Regs {
		diff(t.Errorf, pr.Regs[i], r.Regs[i], fmt.Sprintf("R%d", i))
	}
}

func TestRunLoop(t *testing.T) {
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	t.Logf("IP is %#x", r.Pc)
	r.Pc = 0x100000
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != 0x100000 {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, 0x100000)
	}
	// 0000000000000000 <loop-0x8>:
	// 0:	d503201f 	nop
	// 4:	d503201f 	nop
	// 8:	d42006e0 	brk	#0x37
	nopnophlt := []byte{0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0xe0, 0x06, 0x20, 0xd4}
	if err := v.Write(0x100000, nopnophlt); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}

	for i, pc := range []uint64{0x100004, 0x100008, 0x100008} {
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)

		r, err = v.GetRegs()
		if err != nil {
			t.Fatalf("GetRegs: got %v, want nil", err)
		}
		t.Logf("Registers %#x", r)
		if r.Pc != pc {
			t.Fatalf("iteration %d: got %#x, want %#x", i, r.Pc, pc)
		}
	}
}

// Test whether we can run in low memory.
func TestRunLoop1038(t *testing.T) {
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x1038)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	// 0000000000000000 <loop-0x8>:
	// 0:	d503201f 	nop
	// 4:	d503201f 	nop
	// 8:	d42006e0 	brk	#0x37
	nopnophlt := []byte{0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0xe0, 0x06, 0x20, 0xd4}
	if err := v.Write(uintptr(pc), nopnophlt); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}

	for i, pc := range []uint64{pc + 4, pc + 8, pc + 8} {
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)

		r, err = v.GetRegs()
		if err != nil {
			t.Fatalf("GetRegs: got %v, want nil", err)
		}
		t.Logf("Registers %#x", r)
		if r.Pc != pc {
			t.Fatalf("iteration %d: got %#x, want %#x", i, r.Pc, pc)
		}
	}
}

// Test whether we can run in low memory, and put things on the stack.
func TestRunLoop1038stack(t *testing.T) {
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x1038)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x1000
	r.Regs[0] = 0x100000
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	// a.out:     file format elf64-littleaarch64
	// Disassembly of section .text:
	// 0000000000000000 <loop-0x24>:
	//    0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
	//    4:	910003fd 	mov	x29, sp
	//    8:	f9000fe0 	str	x0, [sp, #24]
	//    c:	f9000be1 	str	x1, [sp, #16]
	//   10:	f9400be1 	ldr	x1, [sp, #16]
	//   14:	f9400fe0 	ldr	x0, [sp, #24]
	//   18:	d503201f 	nop
	//   1c:	d503201f 	nop
	//   20:	d42006e0 	brk	#0x37
	// NOTE: PC should be x1058 on exit.

	// 0000000000000024 <loop>:
	// 	24:	14000000 	b	24 <loop>
	// rminnich@a300:~/go/src/github.com/linuxboot/voodoo/trace/kvm$ aarch64-linux-gnu-objcopy -O binary a.out aaa
	// rminnich@a300:~/go/src/github.com/linuxboot/voodoo/trace/kvm$ xxd -i aaa

	nopnophlt := []byte{
		0xfd, 0x7b, 0xbd, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xe0, 0x0f, 0x00, 0xf9,
		0xe1, 0x0b, 0x00, 0xf9, 0xe1, 0x0b, 0x40, 0xf9, 0xe0, 0x0f, 0x40, 0xf9,
		0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0xe0, 0x06, 0x20, 0xd4,
		0x00, 0x00, 0x00, 0x14}
	if err := v.Write(uintptr(pc), nopnophlt); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}

	for i, pc := range []uint64{pc + 4, pc + 8, pc + 12, pc + 16, pc + 20} {
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)

		r, err = v.GetRegs()
		if err != nil {
			t.Fatalf("GetRegs: got %v, want nil", err)
		}
		t.Logf("Registers %#x", r)
		if r.Pc != pc {
			t.Fatalf("iteration %d: got %#x, want %#x", i, r.Pc, pc)
		}
	}
}

// Test whether we can run in low memory, and put things on the stack, setting the
// stack as the first instruction.
func TestRunLoop1038setstack(t *testing.T) {
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x101028)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x100020
	r.Regs[0] = 0x100000
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	// 0000000000000000 <loop-0x2c>:
	//    0:	d503201f 	nop
	//    4:	9100001f 	mov	sp, x0
	//    8:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
	//    c:	910003fd 	mov	x29, sp
	//   10:	f9000fe0 	str	x0, [sp, #24]
	//   14:	f9000be1 	str	x1, [sp, #16]
	//   18:	f9400be1 	ldr	x1, [sp, #16]
	//   1c:	f9400fe0 	ldr	x0, [sp, #24]
	//   20:	d503201f 	nop
	//   24:	d503201f 	nop
	//   28:	d42006e0 	brk	#0x37

	// 000000000000002c <loop>:
	//   2c:	14000000 	b	2c <loop>
	nopnophlt := []byte{
		0x1f, 0x20, 0x03, 0xd5,
		0x1f, 0x00, 0x00, 0x91,
		0xfd, 0x7b, 0xbd, 0xa9,
		0xfd, 0x03, 0x00, 0x91,
		0xe0, 0x0f, 0x00, 0xf9,
		0xe1, 0x0b, 0x00, 0xf9,
		0xe1, 0x0b, 0x40, 0xf9,
		0xe0, 0x0f, 0x40, 0xf9,
		0x1f, 0x20, 0x03, 0xd5,
		0x1f, 0x20, 0x03, 0xd5,
		0xe0, 0x06, 0x20, 0xd4,
		0x00, 0x00, 0x00, 0x14,
	}
	if err := v.Write(uintptr(pc), nopnophlt); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	for i, pc := range []uint64{pc + 4, pc + 8, pc + 12, pc + 16, pc + 20} {
		_, r, g, err := v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("--------------------> RUN instruction %d, %q @ %#x", i, g, r.Pc)
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)
		_, r, _, err = v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x ", i, g, r.Pc, r.Sp, r.Pstate)

		t.Logf(show(fmt.Sprintf("Instruction %d\t", i), r))
		if r.Pc != pc {
			t.Fatalf("iteration %d: got %#x, want %#x", i, r.Pc, pc)
		}

	}
}

// Test whether we can call the brk42, ret, call it again
func TestBrk42RetBrk42(t *testing.T) {
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x200000)
	base := pc
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x100020
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	// 0000000000100000 <x-0x100008>:
	// 	...
	//   200000:	580000de 	ldr	x30, 200018 <x+0x10>
	//   200004:	d63f03c0 	blr	x30
	//   200008:	d63f03c0 	blr	x30

	// 000000000020000c <x>:
	//   200008:	d4200840 	brk	#0x42
	//   20000c:	d65f03c0 	ret
	//   200010:	d4200840 	brk	#0x42
	//   200014:	00200008 	.word	0x0020000c
	//   200018:	00000000 	.word	0x00000000
	brk42RetBrk42 := []byte{
		0xde, 0x00, 0x00, 0x58,
		0xc0, 0x03, 0x3f, 0xd6,
		0xc0, 0x03, 0x3f, 0xd6,
		0x40, 0x08, 0x20, 0xd4,
		0xc0, 0x03, 0x5f, 0xd6,
		0x40, 0x08, 0x20, 0xd4,
		0x0c, 0x00, 0x20, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	if err := v.Write(uintptr(pc), brk42RetBrk42); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	for i, pc := range []uint64{pc + 4, pc + 0xc} {
		_, r, g, err := v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("--------------------> RUN instruction %d, %q @ %#x", i, g, r.Pc)
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		_, r, _, err = v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x ", i, g, r.Pc, r.Sp, r.Pstate)
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)

		t.Logf(show(fmt.Sprintf("Instruction %d\t", i), r))
		if r.Pc != pc {
			t.Fatalf("iteration %d: got %#x, want %#x", i, r.Pc, pc)
		}
	}
	// Now we need to adjust the pc to return to the ret instruction.
	if r, err = v.GetRegs(); err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	// 32-bit instructions
	r.Pc += 4
	t.Logf("IP is %#x", r.Pc)
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}

	// x30 now contains 0x20008, so we see it twice, that's fine.
	for i, pc := range []uint64{base + 8, base + 8} {
		_, r, g, err := v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("--------------------> RUN instruction %d, %q @ %#x", i, g, r.Pc)
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		_, r, _, err = v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x ", i, g, r.Pc, r.Sp, r.Pstate)
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)

		t.Logf(show(fmt.Sprintf("Instruction %d\t", i), r))
		if r.Pc != pc {
			t.Fatalf("iteration %d: got %#x, want %#x", i, r.Pc, pc)
		}
	}
}

// Test whether the ELREL has what we expect.
func TestELREL(t *testing.T) {
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x200000)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x100020
	//r.ELREL = 0x200000 // convenience only, does not matter
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	// 0000000000100000 <x-0x100008>:
	// 	...
	//   200000:	580000de 	ldr	x30, 200018 <x+0x10>
	//   200004:	d63f03c0 	blr	x30
	//   200008:	d63f03c0 	blr	x30

	// 000000000020000c <x>:
	//   200008:	d4200840 	brk	#0x42
	//   20000c:	d65f03c0 	ret
	//   200010:	d4200840 	brk	#0x42
	//   200014:	00200008 	.word	0x0020000c
	//   200018:	00000000 	.word	0x00000000
	brk42RetBrk42 := []byte{
		0xde, 0x00, 0x00, 0x58,
		0xc0, 0x03, 0x3f, 0xd6,
		0xc0, 0x03, 0x3f, 0xd6,
		0x40, 0x08, 0x20, 0xd4,
		0xc0, 0x03, 0x5f, 0xd6,
		0x40, 0x08, 0x20, 0xd4,
		0x0c, 0x00, 0x20, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	if err := v.Write(uintptr(pc), brk42RetBrk42); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	for i, elr := range []uint64{0x20000c, pc + 8} {
		_, r, g, err := v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("--------------------> RUN instruction %d, %q @ %#x", i, g, r.Pc)
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		_, r, _, err = v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x ", i, g, r.Pc, r.Sp, r.Pstate)
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)

		if r.Regs[ELREL] != elr {
			t.Fatalf("iteration %d: LR got %#x, want %#x", i, r.Regs[ELREL], elr)
		}
	}
}

// TestVMCall tests the ARM64 VMCall code. As in x86, we save 64 bits for this function.
// We want to make sure this works even when SingleStep is not
// set. If Things Go Wrong you can safely enable SingleStep
// (below) and the test will still run until the proper exit condition
// is met, or error if it was not.
func TestVMCall(t *testing.T) {
	inTest = true
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
	pc := uint64(0x100000)
	r.Pc = pc
	r.Sp = 0x100020
	// Simulate a call from the UEFI world.
	r.Regs[30] = 0xff450098
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}

	if err := v.Write(uintptr(pc), VMCall); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	if false {
		if err := v.SingleStep(true); err != nil {
			t.Fatalf("SingleStep: got %v, want nil", err)
		}
	}
	// The MMIO exit is not a call, so the PC will point to the MMIO instruction,
	// not the one after it.
	// Run the loop for 3 instructions, and if we get an mmio, then we're done.
	for i := 0; i < 3; i++ {
		_, r, g, err := v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# RUN instruction %d EIP %#x, SP %#x, PSTATE %#x (%v)", i, r.Pc, r.Sp, r.Pstate, g)
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ins, r, g, err := v.Inst()
		if err != nil {
			r, err = v.GetRegs()
			if err != nil {
				t.Fatalf("GetRegs: got %v, want nil", err)
			}
			t.Logf("====================# FAILED instruction %d, EIP %#x, SP %#x, PSTATE %#x x[8] %#x x[ELREL] %#x", ins, r.Pc, r.Sp, r.Pstate, r.Regs[8], r.Regs[ELREL])
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x x[8] %#x x[ELREL] %#x", ins, g, r.Pc, r.Sp, r.Pstate, r.Regs[8], r.Regs[ELREL])
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("Event %#x, trap %d, %v", ev, ev.Trapno, s)
		// If we ever hit an MMIO, then we're done.
		// This peculiar way of exiting the loop is so that we can
		// enable single stepping (above) when It All Goes Wrong.
		// Which it has.
		if ev.Trapno == ExitMmio {
			return
		}
		t.Errorf("Exit: Got %#x, want ExitMmio (%#x)", ev.Trapno, ExitMmio)
	}
	t.Errorf("After loop: got no ExitMmio, expected one")
}

// TestUEFICall tests the ARM64 UEFI calll code.
// It is a BL x3, followed by the kvm exit code.
// This runs under single step, as even in that case,
// we've seen "issues"
// Test whether the ELREL has what we expect.
// This no longer works and I Just Don't Care -- we have the
// working one below.
func testUEFICall(t *testing.T) {
	inTest = true
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x200000)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x100020
	Debug = t.Logf
	//r.ELREL = 0x200000 // convenience only, does not matter
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	// 200000:	58000000 	ldr	x0, 200000 <.text+0x200000>
	// 200004:	10000063	adr	x3, 200010 <cat>
	// 200008:	d63f0060 	blr	x3
	// 20000c:	91002108 	add	x8, x8, #0x8
	// cat:
	// 200010:	f2c01001 	movk	x1, #0x80, lsl #32
	// 200014:	f9400021 	ldr	x1, [x1]
	// 200018:	f9400021 	ldr	x1, [x1]
	// 20001c:	f9400021 	ldr	x1, [x1]
	// 20001c:	f9400021 	ldr	x1, [x1]
	// 20001c:	f9400021 	ldr	x1, [x1]
	// xxxxxx:	91000421 	add	x1, x1, #0x1
	// xxxxxx:	d65f03c0 	ret
	// xxxxxx:	d42159c0 	brk	#0xace
	// xxxxxx:	91002108 	add	x8, x8, #0x8
	// I have no fucking clue why this is, but in single step mode,
	// it seems to skip the instruction after the MMIO on a resume.
	// So this is the instruction sequence that seems to work for the
	// UEFI call: ldr, mmio, nop instruction, ret. Fuck me.
	code := []byte{
		0x00, 0x00, 0x00, 0x58, // ldr	x0, 200000 <.text+0x200000>
		0x63, 0x00, 0x00, 0x10, // adr	x3, 200010 <cat>
		0x60, 0x00, 0x3f, 0xd6, // blr	x3
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0x01, 0x10, 0xc0, 0xf2, // movk	x1, #0x80, lsl #32
		// increment x8. This tells us we did this instruction.
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0x21, 0x00, 0x40, 0xf9, // ldr	x1, [x1]
		0x09, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0x0a, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0xc0, 0x03, 0x5f, 0xd6,
		0xc0, 0x03, 0x5f, 0xd6,
		0xc0, 0x59, 0x21, 0xd4,
		0xc0, 0x59, 0x21, 0xd4,
		0xc0, 0x59, 0x21, 0xd4,
		0xc0, 0x59, 0x21, 0xd4,
	}
	if err := v.Write(uintptr(pc), code); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	_, r, g, err := v.Inst()
	if err != nil {
		t.Fatalf("Inst: got %v, want nil", err)
	}
	var trapno int
	for i, cur := range []uint64{pc, pc + 4, pc + 8, pc + 0x10, pc + 0x14, pc + 0x18, pc + 0x1c} {
		t.Logf("--------------------> RUN instruction %d, %q @ %#x x1 %#x x3 %#x", i, g, r.Pc, r.Regs[1], r.Regs[3])
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("\t%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)
		_, r, _, err = v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x x1 %#x x3 %#x x8 %#x", i, g, r.Pc, r.Sp, r.Pstate, r.Regs[1], r.Regs[3], r.Regs[8])

		if ev.Trapno == ExitMmio {
			trapno = ExitMmio
			break
		}
		if r.Pc != cur {
			t.Errorf("iteration %d: Pc got %#x, want %#x", i, r.Pc, cur)
		}
		_, r, g, err = v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
	}
	t.Logf("Exited first loop")
	if trapno != ExitMmio {
		t.Fatalf("After first loop: got %v, want %v", trapno, ExitMmio)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Regs[ELREL] != 0x20000c {
		t.Fatalf("After first loop: LR is %#x, want %#x", r.Regs[ELREL], 0x20000c)
	}
	// Now set the PC to what we think it ought to be, verify its setting,
	// then Run and hope things seem right.
	pc = r.Pc
	if true {
		pc = 0x200008
		r.Pc = pc
		if err := v.SetRegs(r); err != nil {
			t.Fatalf("SetRegs: got %v, want nil", err)
		}
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Errorf("PC: got %#x, want %#x", r.Pc, pc)
	}
	if r.Regs[8] != 0x8 {
		t.Errorf("After first loop: x8 is %#x, want 0x8", r.Regs[8])
	}

	t.Logf("Start next loop with pc %#x x8 %#x", r.Pc, r.Regs[8])
	// We exited due to an MMIO. It's turning out we can't mess around with the
	// Pc in the regs -- for whatever reason it is confusing the hell out of kvm.
	// Further, best if we only set the return register, nothing else.
	var x8 uint64
	for i, cur := range []uint64{0x200010, 0x200014, 0x200018} {
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)
		_, r, g, err = v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x x8 %#x x3 %#x", i, g, r.Pc, r.Sp, r.Pstate, r.Regs[8], r.Regs[3])

		if r.Pc != cur {
			t.Errorf("iteration %d: Pc got %#x, want %#x", i, r.Pc, cur)
		}
		x8 = r.Regs[8]
	}
	if x8 != 0x18 {
		t.Errorf("x8: got %#x, want 0x20", x8)
	}
}

func TestDebugSingleStep(t *testing.T) {
	inTest = true
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x200000)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x100020
	Debug = t.Logf
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	code := []byte{
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0xc0, 0x59, 0x21, 0xd4, // d42159c0 	brk	#0xace
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0xc0, 0x59, 0x21, 0xd4, // d42159c0 	brk	#0xace
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0xc0, 0x59, 0x21, 0xd4, // d42159c0 	brk	#0xace
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0xc0, 0x59, 0x21, 0xd4, // d42159c0 	brk	#0xace
	}
	if err := v.Write(uintptr(pc), code); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	_, r, g, err := v.Inst()
	if err != nil {
		t.Fatalf("Inst: got %v, want nil", err)
	}
	// Awesomely, it seems we don't get a break on an instruction past adjusting the Pc
	for i, cur := range []uint64{pc + 4, pc + 12, pc + 20, pc + 28} {
		t.Logf("--------------------> RUN instruction %d, %q @ %#x x8 %#x", i, g, r.Pc, r.Regs[8])
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("\t%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)
		_, r, g, err = v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x x8 %#x", i, g, r.Pc, r.Sp, r.Pstate, r.Regs[8])

		if r.Pc != cur {
			t.Errorf("iteration %d: Pc got %#x, want %#x", i, r.Pc, cur)
		}
		// Disassemblers are your friend
		if g == "brk #0xace" {
			r.Pc += 4
		}
		if err := v.SetRegs(r); err != nil {
			t.Fatalf("SetRegs: got %v, want nil", err)
		}
	}
}

// This does not work. Dammit. how do we get HVC out?
func testDebugRun(t *testing.T) {
	inTest = true
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
	pc := uint64(0x200000)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x100020
	Debug = t.Logf
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	code := []byte{
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0xe3, 0x66, 0x02, 0xd4, // d40266e3 	smc	#0x1337
		0xe2, 0x66, 0x02, 0xd4, // d40266e2 	hvc	#0x1337
		//  		0xc0, 0x59, 0x21, 0xd4, // d42159c0 	brk	#0xace
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0xe2, 0x66, 0x02, 0xd4, // d40266e2 	hvc	#0x1337
		//  		0xc0, 0x59, 0x21, 0xd4, // d42159c0 	brk	#0xace
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0xe2, 0x66, 0x02, 0xd4, // d40266e2 	hvc	#0x1337
		//  		0xc0, 0x59, 0x21, 0xd4, // d42159c0 	brk	#0xace
		0x08, 0x21, 0x00, 0x91, // add	x8, x8, #0x8
		0xe2, 0x66, 0x02, 0xd4, // d40266e2 	hvc	#0x1337
		//  		0xc0, 0x59, 0x21, 0xd4, // d42159c0 	brk	#0xace
	}
	if err := v.Write(uintptr(pc), code); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	_, r, g, err := v.Inst()
	if err != nil {
		t.Fatalf("Inst: got %v, want nil", err)
	}
	// Awesomely, it seems we don't get a break on an instruction past adjusting the Pc
	for i, cur := range []uint64{pc + 4, pc + 12, pc + 20, pc + 28} {
		t.Logf("Regs 0-3: #%x", r.Regs[0:4])
		t.Logf("--------------------> RUN instruction %d, %q @ %#x x8 %#x", i, g, r.Pc, r.Regs[8])
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("\t%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)
		_, r, g, err = v.Inst()
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x x8 %#x", i, g, r.Pc, r.Sp, r.Pstate, r.Regs[8])

		if r.Pc != cur {
			t.Errorf("iteration %d: Pc got %#x, want %#x", i, r.Pc, cur)
		}
		// Disassemblers are your friend
		if g == "brk #0xace" {
			r.Pc += 4
		}
		if err := v.SetRegs(r); err != nil {
			t.Fatalf("SetRegs: got %v, want nil", err)
		}
	}
}

// Test writing to the stack.
func TestSP(t *testing.T) {
	inTest = true
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x200000)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x220000
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	code := []byte{
		0x05, 0x00, 0x00, 0x10, //  200000:	10000005 	adr	x5, 200000 <cat-0x28>
		0x09, 0x00, 0x00, 0x94, //  200004:     94000009 	bl	20074c <cat>
		0x05, 0x00, 0x00, 0x10, //  200008:	10000005 	adr	x5, 200008 <cat-0x20>
		0x07, 0x00, 0x00, 0x94, //  20000c:	94000007 	bl	20074c <cat>
		0x05, 0x00, 0x00, 0x10, //  200010:	10000005 	adr	x5, 200010 <cat-0x18>
		0x05, 0x00, 0x00, 0x94, //  200014:	94000005 	bl	20074c <cat>
		0x05, 0x00, 0x00, 0x10, //  200018:	10000005 	adr	x5, 200018 <cat-0x10>
		0x03, 0x00, 0x00, 0x94, //  20001c:	94000003 	bl	20074c <cat>
		0x05, 0x00, 0x00, 0x10, //  200020:	10000005 	adr	x5, 200020 <cat-0x8>
		0x01, 0x00, 0x00, 0x94, //  200024:	94000001 	bl	20074c <cat>

		//0000000000200028 <cat>:
		0x05, 0x10, 0xc0, 0xf2, //  200028:	f2c01005 	movk	x5, #0x80, lsl #32
		0x3e, 0x7e, 0x0b, 0xd5, //  20002c:	d50b7e3e 	dc	civac, x30
		// what if I told you an invalid address will reset the CPU. It does.
		0xe7, 0x03, 0x00, 0x2a, //  200754:	2a0003e7 	mov	w7, w0
		0x27, 0x7e, 0x0b, 0xd5, //  200758:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x01, 0x2a, //  20075c:	2a0103e7 	mov	w7, w1
		0x27, 0x7e, 0x0b, 0xd5, //  200760:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x02, 0x2a, //  200764:	2a0203e7 	mov	w7, w2
		0x27, 0x7e, 0x0b, 0xd5, //  200768:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x03, 0x2a, //  20076c:	2a0303e7 	mov	w7, w3
		0x27, 0x7e, 0x0b, 0xd5, //  200770:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x04, 0x2a, //  200774:	2a0403e7 	mov	w7, w4
		0x27, 0x7e, 0x0b, 0xd5, //  200778:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x05, 0x2a, //  20077c:	2a0503e7 	mov	w7, w5
		0x27, 0x7e, 0x0b, 0xd5, //  200780:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x06, 0x2a, //  200784:	2a0603e7 	mov	w7, w6
		0x27, 0x7e, 0x0b, 0xd5, //  200788:	d50b7e27 	dc	civac, x7
		0xa5, 0x00, 0x40, 0xf9, //  20004c:	f94000a5 	ldr	x5, [x5]
		0xe5, 0x03, 0x40, 0xf9, // 		f94003e5 	ldr	x5, [sp]
		0xe0, 0x03, 0x05, 0xaa, //  200050:	aa0503e0 	mov	x0, x5
		0xc0, 0x03, 0x5f, 0xd6, //  200054:	d65f03c0 	ret
	}
	if err := v.Write(uintptr(pc), code); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	if err := v.WriteWord(uintptr(r.Sp), 0xdeadbeefcafebad0); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	w, err := v.ReadWord(uintptr(r.Sp))
	if err != nil {
		t.Fatalf("Reading Sp %#x: want no error, got %v", r.Sp, err)
	}
	t.Logf("w at %#x is %#x", r.Sp, w)
	// Awesomely, it seems we don't get a break on an instruction past adjusting the Pc
	t.Logf("Before loop sp %#x, Regs 0-3: #%x", r.Sp, r.Regs[0:4])
	// number iteratons:
	for i := 0; i < 77; i++ {
		_, r, g, err := v.Inst()
		if err != nil {
			t.Logf("Inst: got %v, want nil, proceeding anyway", err)
		}
		t.Logf("--------------------> RUN instruction %d, %q @ %#x SP %#x regs 0-3: %#x", i, g, r.Pc, r.Sp, r.Regs[0:6])
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("\t%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)
		_, r, _, err = v.Inst()
		if err != nil {
			t.Logf("Inst: got %v, want nil, proceeding anyway", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x regs 0-3: %#x", i, g, r.Pc, r.Sp, r.Pstate, r.Regs[0:6])

		if r.Pc < 0x200000 || int(r.Pc) > 0x200000+len(code) {
			t.Fatalf("r.Pc: got %#x, want it to be in range 0x200000-%#x", r.Pc, 0x200000+len(code))
		}
		if i > 1 {
			b := 0x01020304005060700 + uint64(i)
			t.Logf("Rewrite SP %#x to %#x", r.Sp, b)
			if err := v.WriteWord(uintptr(r.Sp), b); err != nil {
				t.Fatalf("Writing br . instruction: got %v, want nil", err)
			}
			w, err := v.ReadWord(uintptr(r.Sp))
			if err != nil {
				t.Fatalf("Reading Sp %#x: want no error, got %v", r.Sp, err)
			}
			t.Logf("w at %#x is %#x", r.Sp, w)
		}
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	t.Logf("Done Sp %#x Regs 0-3: #%x", r.Sp, r.Regs[0:4])
}

// Test writing to the stack.
func TestTramp(t *testing.T) {
	inTest = true
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x200000)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x220000
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	// This models what we have to do in rundxerun, mainly, fill in this slice with the
	// jmp to the trampoline code, which in turn does the DC ops and exits.
	code := []byte{
		0x08, 0xe8, 0xbf, 0xd2, //	d2bfe808 	mov	x8, #0xff400000
		0x00, 0x01, 0x3f, 0xd6, //	d63f0100 	blr	x8
		0xe0, 0x03, 0x40, 0xf9, //   	f94003e0 	ldr	x0, [sp]
		// Just so we don't do a bad insn.
		0xe0, 0x03, 0x40, 0xf9, //   	f94003e0 	ldr	x0, [sp]
		0xe0, 0x03, 0x40, 0xf9, //   	f94003e0 	ldr	x0, [sp]
		0xe0, 0x03, 0x40, 0xf9, //   	f94003e0 	ldr	x0, [sp]
	}

	low16m := []byte{
		//		00000000ff400000 <main>:
		0x08, 0x00, 0x00, 0x10, //      ff400000:	10000008 	adr	x8, ff400000 <main>
		0xff, 0xbf, 0x03, 0x14, //      ff400004:	1403bfff 	b	ff4f0000 <cat>
		0x08, 0x00, 0x00, 0x10, //      ff400008:	10000008 	adr	x8, ff400008 <main+0x8>
		0xfd, 0xbf, 0x03, 0x14, //      ff40000c:	1403bffd 	b	ff4f0000 <cat>
		0x08, 0x00, 0x00, 0x10, //      ff400010:	10000008 	adr	x8, ff400010 <main+0x10>
		0xfb, 0xbf, 0x03, 0x14, //      ff400014:	1403bffb 	b	ff4f0000 <cat>
		0x08, 0x00, 0x00, 0x10, //      ff400018:	10000008 	adr	x8, ff400018 <main+0x18>
		0xf9, 0xbf, 0x03, 0x14, //      ff40001c:	1403bff9 	b	ff4f0000 <cat>
		0x08, 0x00, 0x00, 0x10, //      ff400020:	10000008 	adr	x8, ff400020 <main+0x20>
	}
	top64k := []byte{
		// 00000000ff4f0000 <cat>:
		0x3e, 0x7e, 0x0b, 0xd5, //      ff4f0000:	d50b7e3e 	dc	civac, x30
		0xe7, 0x03, 0x00, 0x2a, //      ff4f0004:	2a0003e7 	mov	w7, w0
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0008:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x01, 0x2a, //      ff4f000c:	2a0103e7 	mov	w7, w1
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0010:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x02, 0x2a, //      ff4f0014:	2a0203e7 	mov	w7, w2
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0018:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x03, 0x2a, //      ff4f001c:	2a0303e7 	mov	w7, w3
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0020:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x04, 0x2a, //      ff4f0024:	2a0403e7 	mov	w7, w4
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0028:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x05, 0x2a, //      ff4f002c:	2a0503e7 	mov	w7, w5
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0030:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x06, 0x2a, //      ff4f0034:	2a0603e7 	mov	w7, w6
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0038:	d50b7e27 	dc	civac, x7
		0x09, 0x10, 0xc0, 0xd2, //      ff4f003c:	f2c01009 	movz	x9, #0x80, lsl #32
		0x29, 0x01, 0x40, 0xf9, //      ff4f0040:	f9400129 	ldr	x9, [x9]
		0xc0, 0x03, 0x5f, 0xd6, //      ff4f0044:	d65f03c0 	ret
	}
	if err := v.Write(0xff400000, low16m); err != nil {
		t.Fatalf("Writing low16m instruction: got %v, want nil", err)
	}
	if err := v.Write(0xff4f0000, top64k); err != nil {
		t.Fatalf("Writing top64k instruction: got %v, want nil", err)
	}
	if err := v.Write(uintptr(pc), code); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	if err := v.WriteWord(uintptr(r.Sp), 0xdeadbeefcafebad0); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	w, err := v.ReadWord(uintptr(r.Sp))
	if err != nil {
		t.Fatalf("Reading Sp %#x: want no error, got %v", r.Sp, err)
	}
	t.Logf("w at %#x is %#x", r.Sp, w)
	// Awesomely, it seems we don't get a break on an instruction past adjusting the Pc
	t.Logf("Before loop sp %#x, Regs 0-3: #%x", r.Sp, r.Regs[0:4])
	// number iteratons:
	for i := 0; i < 26; i++ {
		_, r, g, err := v.Inst()
		if err != nil {
			t.Logf("Inst: got %v, want nil, proceeding anyway", err)
		}
		t.Logf("--------------------> RUN instruction %d, %q @ %#x SP %#x regs 0-5: %#x, x8: %#x", i, g, r.Pc, r.Sp, r.Regs[0:6], r.Regs[8])
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("\t%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)
		_, r, _, err = v.Inst()
		if err != nil {
			t.Logf("Inst: got %v, want nil, proceeding anyway", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x regs 0-5: %#x, x8: %#x", i, g, r.Pc, r.Sp, r.Pstate, r.Regs[0:6], r.Regs[8])

		if i > 1 {
			b := 0x01020304005060700 + uint64(i)
			t.Logf("Rewrite SP %#x to %#x", r.Sp, b)
			if err := v.WriteWord(uintptr(r.Sp), b); err != nil {
				t.Fatalf("Writing sp : got %v, want nil", err)
			}
			w, err := v.ReadWord(uintptr(r.Sp))
			if err != nil {
				t.Fatalf("Reading Sp %#x: want no error, got %v", r.Sp, err)
			}
			t.Logf("w at %#x is %#x", r.Sp, w)
		}
		if r.Pc == 0x200010 {
			break
		}
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Regs[0] != 0x1020304005060715 {
		t.Fatalf("R0: got %#x, want 0x1020304005060715", r.Regs[0])
	}
	t.Logf("Done Sp %#x Regs 0-3: #%x", r.Sp, r.Regs[0:4])
}

// Test writing to the stack using a generate trampoline
func TestGenTramp(t *testing.T) {
	inTest = true
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
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("SingleStep: got %v, want nil", err)
	}
	pc := uint64(0x200000)
	t.Logf("IP is %#x", r.Pc)
	r.Pc = pc
	r.Sp = 0x220000
	if err := v.SetRegs(r); err != nil {
		t.Fatalf("SetRegs: got %v, want nil", err)
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != pc {
		t.Fatalf("PC: got %#x, want %#x", r.Pc, pc)
	}
	// This models what we have to do in rundxerun, mainly, fill in this slice with the
	// jmp to the trampoline code, which in turn does the DC ops and exits.
	code := []byte{
		//0x08, 0xe8, 0xbf, 0xd2, //	d2bfe808 	mov	x8, #0xff400000
		0x08, 0xe9, 0xbf, 0xd2, //	d2bfe908 	mov	x8, #0xff480000
		0x00, 0x01, 0x3f, 0xd6, //	d63f0100 	blr	x8
		0xe0, 0x03, 0x40, 0xf9, //   	f94003e0 	ldr	x0, [sp]
		0x08, 0xe9, 0xbf, 0xd2, //	d2bfe908 	mov	x8, #0xff480000
		0x08, 0xe9, 0xbf, 0xd2, //	d2bfe908 	mov	x8, #0xff480000
		0x08, 0xe9, 0xbf, 0xd2, //	d2bfe908 	mov	x8, #0xff480000
		0x08, 0xe9, 0xbf, 0xd2, //	d2bfe908 	mov	x8, #0xff480000
		// Just so we don't do a bad insn.
		0xe0, 0x03, 0x40, 0xf9, //   	f94003e0 	ldr	x0, [sp]
		0xe0, 0x03, 0x40, 0xf9, //   	f94003e0 	ldr	x0, [sp]
		0xe0, 0x03, 0x40, 0xf9, //   	f94003e0 	ldr	x0, [sp]
	}
	if err := v.Write(uintptr(pc), code); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}

	// Generate the jmps to the trampoline
	var low16m [0x400000 - 0x10000]byte
	for i := 0; i < len(low16m); i += 8 {
		var w uint64 = 0x1403bfff10000008 - (uint64((i/8)*2) << 32)
		binary.LittleEndian.PutUint64(low16m[i:], w)
	}
	if err := v.Write(0xff400000, low16m[:]); err != nil {
		t.Fatalf("Writing low16m instruction: got %v, want nil", err)
	}

	top64k := []byte{
		// 00000000ff4f0000 <cat>:
		0x3e, 0x7e, 0x0b, 0xd5, //      ff4f0000:	d50b7e3e 	dc	civac, x30
		0xe7, 0x03, 0x00, 0x2a, //      ff4f0004:	2a0003e7 	mov	w7, w0
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0008:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x01, 0x2a, //      ff4f000c:	2a0103e7 	mov	w7, w1
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0010:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x02, 0x2a, //      ff4f0014:	2a0203e7 	mov	w7, w2
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0018:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x03, 0x2a, //      ff4f001c:	2a0303e7 	mov	w7, w3
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0020:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x04, 0x2a, //      ff4f0024:	2a0403e7 	mov	w7, w4
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0028:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x05, 0x2a, //      ff4f002c:	2a0503e7 	mov	w7, w5
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0030:	d50b7e27 	dc	civac, x7
		0xe7, 0x03, 0x06, 0x2a, //      ff4f0034:	2a0603e7 	mov	w7, w6
		0x27, 0x7e, 0x0b, 0xd5, //      ff4f0038:	d50b7e27 	dc	civac, x7
		0x09, 0x10, 0xc0, 0xd2, //      ff4f003c:	f2c01009 	movz	x9, #0x80, lsl #32
		0x29, 0x01, 0x40, 0xf9, //      ff4f0040:	f9400129 	ldr	x9, [x9]
		0xc0, 0x03, 0x5f, 0xd6, //      ff4f0044:	d65f03c0 	ret
	}
	if err := v.Write(0xff4f0000, top64k); err != nil {
		t.Fatalf("Writing top64k instruction: got %v, want nil", err)
	}

	if err := v.WriteWord(uintptr(r.Sp), 0xdeadbeefcafebad0); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	w, err := v.ReadWord(uintptr(r.Sp))
	if err != nil {
		t.Fatalf("Reading Sp %#x: want no error, got %v", r.Sp, err)
	}
	t.Logf("w at %#x is %#x", r.Sp, w)
	// Awesomely, it seems we don't get a break on an instruction past adjusting the Pc
	t.Logf("Before loop sp %#x, Regs 0-3: #%x", r.Sp, r.Regs[0:4])
	// number iteratons:
	for i := 0; i < 26; i++ {
		_, r, g, err := v.Inst()
		if err != nil {
			t.Logf("Inst: got %v, want nil, proceeding anyway", err)
		}
		t.Logf("--------------------> RUN instruction %d, %q @ %#x SP %#x regs 0-5: %#x, x8: %#x", i, g, r.Pc, r.Sp, r.Regs[0:6], r.Regs[8])
		if err := v.Run(); err != nil {
			t.Fatalf("Run: got %v, want nil", err)
		}
		ev := v.Event()
		s := unix.Signal(ev.Signo)
		t.Logf("\t%d: Event %#x, trap %d, %v", i, ev, ev.Trapno, s)
		_, r, _, err = v.Inst()
		if err != nil {
			t.Logf("Inst: got %v, want nil, proceeding anyway", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x regs 0-5: %#x, x8: %#x", i, g, r.Pc, r.Sp, r.Pstate, r.Regs[0:6], r.Regs[8])

		if i > 1 {
			b := 0x01020304005060700 + uint64(i)
			t.Logf("Rewrite SP %#x to %#x", r.Sp, b)
			if err := v.WriteWord(uintptr(r.Sp), b); err != nil {
				t.Fatalf("Writing sp : got %v, want nil", err)
			}
			w, err := v.ReadWord(uintptr(r.Sp))
			if err != nil {
				t.Fatalf("Reading Sp %#x: want no error, got %v", r.Sp, err)
			}
			t.Logf("w at %#x is %#x", r.Sp, w)
		}
		if r.Pc == 0x200010 {
			break
		}
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Regs[0] != 0x1020304005060715 {
		t.Fatalf("R0: got %#x, want 0x1020304005060715", r.Regs[0])
	}
	t.Logf("Done Sp %#x Regs 0-3: #%x", r.Sp, r.Regs[0:4])
}
