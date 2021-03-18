package kvm

import (
	"debug/pe"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEFI(t *testing.T) {
	//5 000f 55       	push %rbp
	//6 0010 59       	pop %rcx
	//7 0011 F4       	hlt
	call := []byte{0x55, 0x59, 0xf4}
	Debug = t.Logf
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
	if err := v.SingleStep(false); err != nil {
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
	eip := base + uintptr(h.BaseOfCode)
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
		// Zero it out.
		t.Logf("Copy section to %#x:%#x", addr, s.VirtualSize)
		bb := make([]byte, s.VirtualSize)
		for i := range bb {
			bb[i] = 0x90
		}
		if err := v.Write(addr, bb); err != nil {
			t.Fatalf("Can't write %d bytes of zero @ %#x for this section to process:%v", len(bb), addr, err)
		}
		if false {
			if err := v.Write(addr, dat); err != nil {
				t.Fatalf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
			}
		}
	}

	copy(v.regions[0].data[0x10000:], call)
	const rbp, startpc, startsp, pc, sp = 0x3afef00dd00dfeed, 0x401000, 0x80000, 0x401003, 0x80000
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
	if ev.Trapno != uint32(unix.SIGILL) {
		t.Errorf("Trapno: got %#x, want %v", ev.Trapno, unix.SIGILL)
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
	i, r, err := v.Inst()
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
	if r.Rbp != r.Rcx {
		t.Fatalf("Check rcx: got %#x, want %#x", r.Rcx, r.Rbp)
	}
}
