package kvm

import (
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
	r, err := t.GetRegs()
	if err != nil {
		return nil, nil, "", fmt.Errorf("Inst:Getregs:%v", err)
	}
	pc := r.Pc
	insn := make([]byte, 16)
	if err := t.Read(uintptr(pc), insn); err != nil {
		return nil, nil, "", fmt.Errorf("Can' read PC at #%x, err %v", pc, err)
	}
	d, err := arm64asm.Decode(insn)
	if err != nil {
		return nil, nil, "", fmt.Errorf("Can't decode %#02x: %v", insn, err)
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
			t.Logf("====================# FAILED instruction %d, EIP %#x, SP %#x, PSTATE %#x x[1] %#x x[ELREL] %#x", ins, r.Pc, r.Sp, r.Pstate, r.Regs[1],r.Regs[ELREL] )
			t.Fatalf("Inst: got %v, want nil", err)
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x x[1] %#x x[ELREL] %#x", ins, g, r.Pc, r.Sp, r.Pstate, r.Regs[1],r.Regs[ELREL] )
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
