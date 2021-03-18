// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,amd64

package main

import (
	"debug/pe"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"

	"github.com/linuxboot/voodoo/services"
	"github.com/linuxboot/voodoo/trace"
	"github.com/linuxboot/voodoo/trace/kvm"
	"golang.org/x/sys/unix"
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
	a := flag.Args()
	if len(a) != 1 {
		log.Fatal("arg count")
	}

	t, err := trace.New("kvm")
	if err != nil {
		log.Fatalf("Unknown tracer %s", "kvm")
	}
	if err := t.NewProc(0); err != nil {
		log.Fatalf("Newproc: %v", err)
	}
	st, err := services.Base("systemtable")
	if err != nil {
		log.Fatal(err)
	}
	if *optional {
		trace.RegsPrint = trace.AllregsPrint
	}
	if *singlestep {
		step = any
	}
	// kvm starts life with a memory segment attached.
	// ptrace will need one set up, but there's no
	// reason to do that in main any more. ptrace
	// will have have to adapt.

	if err := t.SingleStep(*singlestep); err != nil {
		log.Printf("First single step: %v", err)
	}
	step()
	// For now, we do the PE/COFF externally. But leave this here ...
	// you never know.

	// Now fill it up
	f, err := pe.Open(flag.Args()[0])
	if err != nil {
		log.Fatal(err)
	}
	h, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		log.Fatalf("File type is %T, but has to be %T", f.OptionalHeader, pe.OptionalHeader64{})
	}
	log.Print(show("", h))
	log.Print(show("", &f.FileHeader))
	// UEFI provides no symbols, of course. Why would it?
	log.Printf("%v:\n%d syms", f, len(f.COFFSymbols))
	for _, s := range f.COFFSymbols {
		log.Printf("\t%v", s)
	}
	// We need to relocate to start at *offset.
	// UEFI runs in page zero. I can't believe it.
	base := uintptr(h.ImageBase)
	eip := base + uintptr(h.BaseOfCode)
	heap := base + uintptr(h.SizeOfImage)
	// heap is at end  of the image.
	// Stack goes at top of reserved stack area.
	sp := heap + uintptr(h.SizeOfHeapReserve+h.SizeOfStackReserve)
	totalsize := int(h.SizeOfImage) + int(h.SizeOfHeapReserve+h.SizeOfStackReserve)
	if err := t.Write(base, make([]byte, totalsize)); err != nil {
		log.Fatalf("Can't write %d bytes of zero @ %#x for this section to process:%v", totalsize, base, err)
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
		// Zero it out.
		log.Printf("Copy section to %#x:%#x", addr, s.VirtualSize)
		bb := make([]byte, s.VirtualSize)
		for i := range bb {
			bb[i] = 0x90
		}
		if err := t.Write(addr, bb); err != nil {
			any(fmt.Sprintf("Can't write %d bytes of zero @ %#x for this section to process:%v", len(bb), addr, err))
			log.Fatalf("Can't write %d bytes of zero @ %#x for this section to process:%v", len(bb), addr, err)
		}
		if false {
			if err := t.Write(addr, dat); err != nil {
				any(fmt.Sprintf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err))
				log.Fatalf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
			}
		}
	}
	trace.SetDebug(log.Printf)

	log.Printf("Start at %#x", eip)
	if false {
		if err := trace.SetIPtr(t, uintptr(eip)); err != nil {
			log.Fatalf("Can't set IPtr to %#x: %v", eip, err)
		}
		if err := trace.Params(t, uintptr(services.ImageHandle), uintptr(st)); err != nil {
			log.Fatalf("Setting params: %v", err)
		}
	}
	if err := trace.Header(os.Stdout); err != nil {
		log.Fatal(err)
	}
	line++
	r, err := t.GetRegs()
	if err != nil {
		log.Fatalf("Could not get regs: %v", err)
	}
	log.Printf("IPtr is %#x, let's go.", eip)
	if err := trace.Regs(os.Stdout, r); err != nil {
		log.Fatal(err)
	}
	p := r
	r.Rsp = uint64(sp)
	r.Rip = uint64(eip)
	// Reserve space for structs that we will place into the memory.
	// We'll try putting it in the bios area.
	services.SetAllocator(0xff000000, 0xff100000)

	log.Printf("Set stack to %#x", r.Rsp)
	if err := t.SetRegs(r); err != nil {
		log.Fatalf("Can't set stack to %#x: %v", dat, err)
	}
	r, err = t.GetRegs()
	if err != nil {
		log.Fatalf("Could not get regs: %v", err)
	}
	if err := trace.Regs(os.Stdout, r); err != nil {
		log.Fatal(err)
	}
	//type Siginfo struct {
	//Signo  int // signal number
	//Errno  int // An errno value
	//Code   int // signal code
	//Trapno int // trap number that caused hardware-generated signal

	//Addr uintptr // Memory location which caused fault
	// We have the tracer, and only one. The tracer
	// will feed us a set of SigInfo's
	{
		insn, r, err := trace.Inst(t)
		if err != nil {
			log.Printf("first inst Inst %v", err)
		} else {

			first := trace.Asm(insn, r.Rip)
			fmt.Print("First instruction: %s", first)
		}
	}
	go func() {
		if err := t.Run(); err != nil {
			log.Printf("First single step: %v", err)
		}
	}()
	for i := range t.Events() {
		line++
		// This fail needs to be fixed in the ptrace package, not here.
		// Hard to say what it is but ... fix it there.
		// // Sometimes it fails with ESRCH but the process is there.
		// // will need to restore this if we ever want ptrace back.
		// i, err := t.GetSigInfo()
		// for err != nil {
		// 	log.Printf("%v,", err)
		// 	i, err = t.GetSigInfo()
		// 	any("Waiting for ^C, or hit return to try GetSigInfo again")
		// }
		log.Printf("SIGNAL INFO: %s", showinfo(&i))
		s := unix.Signal(i.Signo)
		insn, r, err := trace.Inst(t)
		if err != nil {
			if err == io.EOF {
				fmt.Println("\n===:DXE Exits!")
				os.Exit(0)
			}
			log.Fatalf("Could not get regs: %v", err)
		}
		step()
		switch {
		default:
			log.Printf("Can't do %#x(%v)", i.Signo, unix.SignalName(s))
			for {
				any("Waiting for ^C")
			}
		case s == unix.SIGILL:
			log.Printf("SIGILL. you are ILL")
			if err := trace.Regs(os.Stdout, r); err != nil {
				log.Fatal(err)
			}
			illasm := trace.Asm(insn, r.Rip)
			fmt.Println(illasm)
		case s == unix.SIGSEGV:
			// So far, there seem to be three things that can happen.
			// Call, Load, and Store.
			// We don't want to get into pulling apart instructions
			// to figure out which it is; the Asm and other instructions
			// can go a long way toward helping us instead.
			// Figure out it is a Call is easy: does the assembly start with CALL?
			// Done.
			// Next is figuring out if it is a load or store and that
			// is similarly easy. Is Arg[0] a memory address? Then it's a store.
			// We know of no usage of memory-to-memory so we should be safe.
			// Now don't use the miss the ARM already? We sure do. On that one
			// it's easy.
			//showone(os.Stderr, "", &r)
			//any(fmt.Sprintf("Handle the segv at %#x", i.Addr))
			if err := trace.Regs(os.Stdout, r); err != nil {
				log.Fatal(err)
			}
			segvasm := trace.Asm(insn, r.Rip)
			if err := segv(t, &i, insn, r, segvasm); err != nil {
				if err == io.EOF {
					fmt.Println("\n===:DXE Exits!")
					os.Exit(0)
				}
				//showone(os.Stderr, "", &r)
				log.Printf("Can't do %#x(%v): %v", i.Signo, unix.SignalName(s), err)
				for {
					any("Waiting for ^C")
				}
			}
			// The handlers will always change, at least, eip, so just blindly set them
			// back. TODO: see if we need more granularity.
			if err := t.SetRegs(r); err != nil {
				log.Fatalf("Can't set stack to %#x: %v", dat, err)
			}

			if err := t.ReArm(); err != nil {
				//log.Printf("ClearSignal failed; %v", err)
				for {
					any("Waiting for ^C")
				}
			}
			//Debug(showone("", &r))
			any("move along")

		case s == unix.SIGTRAP:
			log.Println("signtrap")
		case i.Trapno == uint32(kvm.ExitShutdown):
			illasm := trace.Asm(insn, r.Rip)
			fmt.Println(illasm)
			illasm = trace.Asm(insn, uint64(eip))
			fmt.Println(illasm)
			log.Printf("Shutdown, sorry!")
		case i.Trapno == uint32(kvm.ExitMmio):
		}

		if err := trace.RegDiff(os.Stdout, r, p); err != nil {
			log.Fatal(err)
		}
		asm := trace.Asm(insn, r.Rip)
		fmt.Println(asm)
		if line%25 == 0 {
			trace.Header(os.Stdout)
		}
		p = r
		go func() {
			if err := t.Run(); err != nil {
				log.Printf("First single step: %v", err)
			}
		}()
		if false {
			if err := t.Run(); err != nil {
				log.Print(err)
			}
		}
	}
}
