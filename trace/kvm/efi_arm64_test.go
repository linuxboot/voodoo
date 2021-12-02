package kvm

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

const callVal = 0xaa55eeee

// Test writing to the stack using a generate trampoline
func TestEFITest(t *testing.T) {
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
	pc := uint64(0x1038)
	r.Pc = pc
	t.Logf("IP is %#x", r.Pc)
	r.Sp = 0x220000
	// Set arg0 and arg1, arg0 in particular can not be 0, and arg1 must be valid pointer
	r.Regs[0] = 0xfeedfacefeedbeef
	r.Regs[1] = 0xff000000
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

	var efitest = []uint32{
		0x1038 / 4: 0xa9bc7bfd, //stp	x29, x30, [sp, #-64]!
		0x103c / 4: 0x910003fd, //mov	x29, sp
		0x1040 / 4: 0xf9000fe0, //str	x0, [sp, #24]
		0x1044 / 4: 0xf9000be1, //str	x1, [sp, #16]
		0x1048 / 4: 0xf9400be1, //ldr	x1, [sp, #16]
		0x104c / 4: 0xf9400fe0, //ldr	x0, [sp, #24]
		0x1050 / 4: 0x9400079d, //bl	2ec4 <InitializeLib>
		//0000000000002ec4<,//InitializeLib>/4:
		0x2ec4 / 4: 0xa9bd7bfd, //stp	x29, x30, [sp, #-48]!
		0x2ec8 / 4: 0x90000062, //adrp	x2, e000 <buf.0>
		0x2ecc / 4: 0x910003fd, //mov	x29, sp
		0x2ed0 / 4: 0xa90153f3, //stp	x19, x20, [sp, #16]
		0x2ed4 / 4: 0xaa0103f4, //mov	x20, x1
		0x2ed8 / 4: 0x39414041, //ldrb	w1, [x2, #80]
		0x2edc / 4: 0xaa0003f3, //mov	x19, x0
		0x2ee0 / 4: 0x35000401, //cbnz	w1, 2f60 <InitializeLib+0x9c>
		0x2ee4 / 4: 0x90000065, //adrp	x5, e000 <buf.0>
		0x2ee8 / 4: 0x90000061, //adrp	x1, e000 <buf.0>
		0x2eec / 4: 0x90000063, //adrp	x3, e000 <buf.0>
		0x2ef0 / 4: 0x90000066, //adrp	x6, e000 <buf.0>
		0x2ef4 / 4: 0x90000064, //adrp	x4, e000 <buf.0>
		0x2ef8 / 4: 0x3901c0bf, //strb	wzr, [x5, #112]
		0x2efc / 4: 0xf9002420, //str	x0, [x1, #72]
		0x2f00 / 4: 0xa9458685, //ldp	x5, x1, [x20, #88]
		0x2f04 / 4: 0xf9001c61, //str	x1, [x3, #56]
		0x2f08 / 4: 0xf90020d4, //str	x20, [x6, #64]
		0x2f0c / 4: 0x52800023, //mov	w3, #0x1                   	// #1
		0x2f10 / 4: 0xf9003c85, //str	x5, [x4, #120]
		0x2f14 / 4: 0x39014043, //strb	w3, [x2, #80]
		0x2f18 / 4: 0xb40001c0, //cbz	x0, 2f50 <InitializeLib+0x8c>
		0x2f1c / 4: 0xf9404c23, //ldr	x3, [x1, #152]
		0x2f20 / 4: 0x9100a3e2, //add	x2, sp, #0x28
		0x2f24 / 4: 0xb0000041, //adrp	x1, b000 <reset_message>
		0x2f28 / 4: 0x911fe021, //add	x1, x1, #0x7f8
		0x2f2c / 4: 0xd63f0060, //blr	x3
		0x2f30 / 4: 0xb7f800a0, //tbnz	x0, #63, 2f44 <InitializeLib+0x80>
		0x2f34 / 4: 0xf94017e1, //ldr	x1, [sp, #40]
		0x2f38 / 4: 0xf94017e1, //ldr	x1, [sp, #40]
		0x2f3c / 4: 0xf94017e1, //ldr	x1, [sp, #40]
		0x2f40 / 4: 0xf94017e1, //ldr	x1, [sp, #40]
		0x2f44 / 4: 0xf94017e1, //ldr	x1, [sp, #40]
		0x2f48 / 4: 0xf94017e1, //ldr	x1, [sp, #40]
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, efitest[:]); err != nil {
		t.Fatalf("Writing efitest to buf: got %v, want nil", err)
	}
	t.Logf("Write to 0x1000, %d bytes, first 32 are %#x", b.Len(), b.Bytes()[0x1000:0x1000+128])
	if err := v.Write(0, b.Bytes()); err != nil {
		t.Fatalf("Writing bytes for efitest to buf: got %v, want nil", err)
	}

	if err := v.WriteWord(0xff000000+0x60, 0xff050000); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}

	//        ST = SystemTable;
	//        BS = SystemTable->BootServices;
	//        RT = SystemTable->RuntimeServices;
	// 1970/01/01 16:34:19 system table u is 0xff000000
	// 1970/01/01 16:34:19 Install 0xff050000 at off 0x60
	// 1970/01/01 16:34:19 Install 0xff400058 at off 0x58
	// 1970/01/01 16:34:19 Install 0xff450098 at off 0x50098
	st := uintptr(0xff000000)
	bs := (st + 0x60)
	rt := (st + 0x58)
	t.Logf("st %#x bs %#x rt %#x", st, bs, rt)
	if err := v.WriteWord(bs, 0xff050000); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	if err := v.WriteWord(0xff050098, 0xff450098); err != nil {
		t.Fatalf("Writing br . instruction: got %v, want nil", err)
	}
	w, err := v.ReadWord(0x1038)
	if err != nil {
		t.Fatalf("Reading Sp %#x: want no error, got %v", r.Sp, err)
	}
	t.Logf("w at %#x is %#x", 0x1038, w)
	// Awesomely, it seems we don't get a break on an instruction past adjusting the Pc
	t.Logf("Before loop sp %#x, Regs 0-3: #%x", r.Sp, r.Regs[0:4])

	var ptr uintptr
	// number iteratons:
	for i := 0; i < 100; i++ {
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
		if ev.Trapno == ExitMmio {
			ptr = uintptr(r.Regs[2])
			t.Logf("MMIO trap, emulate store through arg[2] (%#x) of a value (%#x)", ptr, callVal)
			if err := v.WriteWord(ptr, callVal); err != nil {
				t.Fatalf("Writing value to %#x: got %v, want nil", ptr, err)
			}
		}
		t.Logf("====================# DONE instruction %d, %q, EIP %#x, SP %#x, PSTATE %#x regs 0-5: %#x, x8: %#x", i, g, r.Pc, r.Sp, r.Pstate, r.Regs[0:6], r.Regs[8])

		if r.Pc == 0x2f38 || r.Pc == 0x2f48 {
			break
		}
	}
	r, err = v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	if r.Pc != 0x2f38 && r.Pc != 0x2f48 {
		t.Errorf("Loop exited: r.Pc: got %#x, want 0x2f38", r.Pc)
	}
	if w, err = v.ReadWord(ptr); err != nil {
		t.Fatalf("Reading ptr %#x: want no error, got %v", ptr, err)
	}
	if w != callVal {
		t.Fatalf("memory at %#x: got %#x, want %#x", ptr, w, callVal)
	}
	if r.Regs[1] != callVal {
		t.Errorf("x1: got %#x, want %#x", r.Regs[1], callVal)
	}

	t.Logf("Done Sp %#x Regs 0-3: #%x", r.Sp, r.Regs[0:4])
}
