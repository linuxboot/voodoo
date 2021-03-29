package kvm

import (
	"debug/pe"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestEFI(t *testing.T) {
	//5 000f 55       	push %rbp
	//6 0010 59       	pop %rcx
	//7 0011 F4       	hlt
	call := []byte{0x55, 0x59, 0xf4}
	f, err := pe.Open("data/test.efi")
	if err != nil {
		t.Fatal(err)
	}
	v, err := New()
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	defer v.Detach()
	if err := v.NewProc(0); err != nil {
		t.Fatalf("NewProc: got %v, want nil", err)
	}
	if err := v.SingleStep(true); err != nil {
		t.Fatalf("Run: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}

	h, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("File type is %T, but has to be %T", f.OptionalHeader, pe.OptionalHeader64{})
	}
	// UEFI provides no symbols, of course. Why would it?
	t.Logf("%v:\n%d syms", f, len(f.COFFSymbols))
	for _, s := range f.COFFSymbols {
		t.Logf("\t%v", s)
	}
	// We need to relocate to start at *offset.
	// UEFI runs in page zero. I can't believe it.
	base := uintptr(h.ImageBase)
	eip := uint64(base + uintptr(h.BaseOfCode))
	heap := base + uintptr(h.SizeOfImage)

	// heap is at end  of the image.
	// Stack goes at top of reserved stack area.
	efisp := heap + uintptr(h.SizeOfHeapReserve+h.SizeOfStackReserve)

	t.Logf("base %#x eip %#x efisp %#x", heap, eip, efisp)
	efitotalsize := int(h.SizeOfImage) + int(h.SizeOfHeapReserve+h.SizeOfStackReserve)
	if err := v.Write(base, make([]byte, efitotalsize)); err != nil {
		t.Fatalf("Can't write %d bytes of zero @ %#x for this section to process:%v", efitotalsize, base, err)
	}

	t.Logf("Base is %#x", base)
	for i, s := range f.Sections {
		fmt.Fprintf(os.Stderr, "Section %d", i)
		fmt.Fprintf(os.Stderr, show("\t", &s.SectionHeader))
		addr := base + uintptr(s.VirtualAddress)
		dat, err := s.Data()
		if err != nil {
			t.Fatalf("Can't get data for this section: %v", err)
		}
		if len(dat) == 0 {
			continue
		}
		// Zero it out.
		t.Logf("Copy section to %#x:%#x", addr, s.VirtualSize)
		bb := make([]byte, s.VirtualSize)
		for i := range bb {
			bb[i] = 0
		}
		if true {
			if err := v.Write(addr, bb); err != nil {
				t.Fatalf("Can't write %d bytes of zero @ %#x for this section to process:%v", len(bb), addr, err)
			}
		}
		if err := v.Write(addr, dat[:]); err != nil {
			t.Fatalf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
		}
	}
	Debug = t.Logf
	if false {
		bb := []byte{0xf4}
		const x = 0x709412bb // 0x70945520 // 0x7094127e // 7094122e
		if err := v.Write(x, bb[:]); err != nil {
			t.Fatalf("Write(%#x, %#x): got %v, want nil", x, len(call), err)
		}

		t.Logf("What's at %#x: %s", eip, hex.Dump(bb[:]))
	}
	if true {
		var bb [16]byte
		if err := v.Read(uintptr(eip), bb[:]); err != nil {
			t.Fatalf("Write(%#x, %#x): got %v, want nil", eip, len(call), err)
		}

		t.Logf("What's at %#x: %s", eip, hex.Dump(bb[:]))
	}
	if false {
		call[1] = 0xf4
		if err := v.Write(uintptr(eip+1), call); err != nil {
			t.Fatalf("Write(%#x, %#x): got %v, want nil", eip, len(call), err)
		}
		var bb [16]byte
		if err := v.Read(uintptr(eip), bb[:]); err != nil {
			t.Fatalf("Write(%#x, %#x): got %v, want nil", eip, len(call), err)
		}

		t.Logf("What's at %#x: %s", eip, hex.Dump(bb[:]))
	}

	const rbp = 0x3afef00dd00dfeed

	// When it does the final return, it has to halt.
	// Put a halt on top of stack, and point top of stack to it.
	if err := v.WriteWord(efisp, 0xf4f4f4f4f4f4f4f4); err != nil {
		t.Fatalf("Writing halts at %#x: got %v, want nil", efisp, err)
	}

	sp := uint64(efisp)
	efisp -= 8
	if err := v.WriteWord(efisp, sp); err != nil {
		t.Fatalf("Writing stack %#x at %#x: got %v, want nil", efisp, efisp-8, err)
	}
	//pc := uint64(efisp)
	r.Rip = eip
	r.Rbp = rbp
	r.Rsp = uint64(efisp)
	r.Eflags |= 0x100

	if err := v.SetRegs(r); err != nil {
		t.Fatalf("GetRegs: got %v, want nil", err)
	}
	Debug = t.Logf

	for {
		go func() {
			if err := v.Run(); err != nil {
				t.Errorf("Run: got %v, want nil", err)
			}
		}()
		ev := <-v.Events()
		t.Logf("Event %#x", ev)
		if ev.Trapno != ExitDebug {
			t.Logf("Trapno: got %#x", ev.Trapno)
			break
		}
		r, err = v.GetRegs()
		if err != nil {
			t.Fatalf("GetRegs: got %v, want nil", err)
		}
		t.Logf("REGS: %s", show("", r))
		e := v.cpu.VMRun.String()
		t.Logf("IP is %#x, exit %s", r.Rip, e)
		if r.Rip < uint64(base) {
			break
		}
		i, r, g, err := v.Inst()
		t.Logf("Inst returns %v, %v, %v, %v", i, r, g, err)
		t.Logf("CODE:%v", g)
		if err != nil {
			t.Fatalf("Inst: got %v, want nil", err)
		}
	}
	t.Logf("Rsp is %#x", r.Rsp)
	if r.Rsp != sp {
		t.Fatalf("SP: got %#x, want %#x", r.Rsp, sp)
	}
	check, err := v.ReadWord(efisp + 8)
	if err != nil {
		t.Fatalf("Reading back word from SP@%#x: got %v, want nil", sp-8, err)
	}
	if check != rbp {
		t.Fatalf("Check from memory: got %#x, want %#x", check, rbp)
	}
	if r.Rbp != r.Rcx {
		t.Fatalf("Check rcx: got %#x, want %#x", r.Rcx, r.Rbp)
	}
}
