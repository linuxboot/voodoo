// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,amd64

package main

import (
	"debug/pe"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"

	"github.com/linuxboot/voodoo/trace"
	"github.com/linuxboot/voodoo/trace/kvm"
)

const ()

var ()

type msg func()

var (
	optional   = flag.Bool("optional", false, "Print optional registers")
	singlestep = flag.Bool("singlestep", false, "single step instructions")
	debug      = flag.Bool("debug", true, "Enable debug prints")
	v          = log.Printf
	step       = func(...string) {}
	dat        uintptr
	line       int
)

func any(f ...string) {
	var b [1]byte
	for _, ff := range f {

		log.Println(ff)
	}
	log.Printf("hit the any key")
	os.Stdin.Read(b[:])
}

func showone(indent string, in interface{}) string {
	var ret string
	s := reflect.ValueOf(in).Elem()
	typeOfT := s.Type()

	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		switch f.Kind() {
		case reflect.String:
			ret += fmt.Sprintf(indent+"\t%s %s = %s\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
		default:
			ret += fmt.Sprintf(indent+"\t%s %s = %#x\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
		}
	}
	return ret
}
func show(indent string, l ...interface{}) string {
	var ret string
	for _, i := range l {
		ret += showone(indent, i)
	}
	return ret
}

func main() {
	flag.Parse()
	a := flag.Args()[0]
	f, err := pe.Open(a)
	if err != nil {
		log.Fatal(err)
	}

	v, err := trace.New("kvm")
	if err != nil {
		log.Fatalf("Open: got %v, want nil", err)
	}
	//	defer v.Detach()
	if err := v.NewProc(0); err != nil {
		log.Fatalf("NewProc: got %v, want nil", err)
	}
	if err := v.SingleStep(true); err != nil {
		log.Fatalf("Run: got %v, want nil", err)
	}
	r, err := v.GetRegs()
	if err != nil {
		log.Fatalf("GetRegs: got %v, want nil", err)
	}

	h, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		log.Fatalf("File type is %T, but has to be %T", f.OptionalHeader, pe.OptionalHeader64{})
	}
	// UEFI provides no symbols, of course. Why would it?
	log.Printf("%v:\n%d syms", f, len(f.COFFSymbols))
	for _, s := range f.COFFSymbols {
		log.Printf("\t%v", s)
	}
	// We need to relocate to start at *offset.
	// UEFI runs in page zero. I can't believe it.
	base := uintptr(h.ImageBase)
	eip := uint64(base + uintptr(h.BaseOfCode))
	heap := base + uintptr(h.SizeOfImage)

	// heap is at end  of the image.
	// Stack goes at top of reserved stack area.
	efisp := heap + uintptr(h.SizeOfHeapReserve+h.SizeOfStackReserve)

	log.Printf("base %#x eip %#x efisp %#x", heap, eip, efisp)
	efitotalsize := int(h.SizeOfImage) + int(h.SizeOfHeapReserve+h.SizeOfStackReserve)
	if err := v.Write(base, make([]byte, efitotalsize)); err != nil {
		log.Fatalf("Can't write %d bytes of zero @ %#x for this section to process:%v", efitotalsize, base, err)
	}

	log.Printf("Base is %#x", base)
	for i, s := range f.Sections {
		fmt.Fprintf(os.Stderr, "Section %d", i)
		fmt.Fprintf(os.Stderr, show("\t", &s.SectionHeader))
		addr := base + uintptr(s.VirtualAddress)
		dat, err := s.Data()
		if err != nil {
			log.Fatalf("Can't get data for this section: %v", err)
		}
		if len(dat) == 0 {
			continue
		}
		// Zero it out.
		log.Printf("Copy section to %#x:%#x", addr, s.VirtualSize)
		bb := make([]byte, s.VirtualSize)
		for i := range bb {
			bb[i] = 0
		}
		if true {
			if err := v.Write(addr, bb); err != nil {
				log.Fatalf("Can't write %d bytes of zero @ %#x for this section to process:%v", len(bb), addr, err)
			}
		}
		if err := v.Write(addr, dat[:]); err != nil {
			log.Fatalf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
		}
	}
	trace.Debug = log.Printf
	// When it does the final return, it has to halt.
	// Put a halt on top of stack, and point top of stack to it.
	if err := trace.WriteWord(v, efisp, 0xf4f4f4f4f4f4f4f4); err != nil {
		log.Fatalf("Writing halts at %#x: got %v, want nil", efisp, err)
	}

	sp := uint64(efisp)
	efisp -= 8
	if err := trace.WriteWord(v, efisp, sp); err != nil {
		log.Fatalf("Writing stack %#x at %#x: got %v, want nil", efisp, efisp-8, err)
	}
	//pc := uint64(efisp)
	r.Rip = eip

	r.Rsp = uint64(efisp)
	r.Eflags |= 0x100

	// bogus params to see if we can manages a segv
	//r.Rcx = uint64(imageHandle)
	//r.Rdx = uint64(systemTable)

	if err := v.SetRegs(r); err != nil {
		log.Fatalf("GetRegs: got %v, want nil", err)
	}
	trace.Debug = log.Printf

	for {
		go func() {
			if err := v.Run(); err != nil {
				log.Fatalf("Run: got %v, want nil", err)
			}
		}()
		ev := <-v.Events()
		log.Printf("Event %#x", ev)
		if ev.Trapno != kvm.ExitDebug {
			log.Printf("Trapno: got %#x", ev.Trapno)
			break
		}
		r, err = v.GetRegs()
		if err != nil {
			log.Fatalf("GetRegs: got %v, want nil", err)
		}
		log.Printf("REGS: %s", show("", r))
		//		e := ev.cpu.VMRun.String()
		//		log.Printf("IP is %#x, exit %s", r.Rip, e)

		i, r, err := trace.Inst(v)
		if err != nil {
			log.Fatalf("Inst: got %v, want nil", err)
		}
		log.Printf("Inst returns %v, %v, %v", i, r, err)
	}
	log.Printf("Rsp is %#x", r.Rsp)
	// we "just know" for now.
	if r.Rsp != 0x70c4ff70 {
		log.Fatalf("SP: got %#x, want %#x", r.Rsp, 0x70c4ff70)
	}
}
