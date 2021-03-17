// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,amd64

package main

import (
	"debug/elf"
	"debug/pe"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"reflect"

	"github.com/linuxboot/voodoo/services"
	"github.com/linuxboot/voodoo/trace"
	"golang.org/x/sys/unix"
)

const ()

var ()

type msg func()

var (
	start      = flag.Uint64("start", 0, "starting address -- default is from PE/COFF but you can override")
	optional   = flag.Bool("optional", false, "Print optional registers")
	offset     = flag.Uint64("offset", 0x400000, "offset for objcopy")
	singlestep = flag.Bool("singlestep", false, "single step instructions")
	debug      = flag.Bool("debug", true, "Enable debug prints")
	elfFile    = flag.String("elf", "binstart", "file to use for initial ptrace startup")
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
	// objcopy seems to corrupt the file, too bad!
	if false {
		f, err := ioutil.TempFile("", "voodoo")
		if err != nil {
			log.Fatal(err)
		}
		*elfFile = f.Name()
		o, err := exec.Command("objcopy", "--adjust-vma", fmt.Sprintf("%#x", *offset), "-O", "elf64-x86-64", a[0], *elfFile).CombinedOutput()
		if err != nil {
			log.Fatalf("objcopy to %s failed: %s %v", *elfFile, string(o), err)
		}
		f.Close()
	}
	e, err := elf.Open(*elfFile)
	if err != nil {
		log.Fatal(err)
	}
	eip := uintptr(e.Entry)
	e.Close()
	if err := t.Exec(*elfFile, []string{*elfFile}...); err != nil {
		log.Fatal(err)
	}
	//	log.Printf("Process started with PID %d", t.PID())
	step()
	if err := t.SingleStep(*singlestep); err != nil {
		log.Printf("First single step: %v", err)
	}
	step()
	if err := t.Run(); err != nil {
		log.Printf("First single step: %v", err)
	}
	// For now, we do the PE/COFF externally. But leave this here ...
	// you never know.
	if true {
		// Now fill it up
		f, err := pe.Open(flag.Args()[0])
		if err != nil {
			log.Fatal(err)
		}
		log.Print(show("", &f.FileHeader))
		// UEFI provides no symbols, of course. Why would it?
		log.Printf("%v:\n%d syms", f, len(f.COFFSymbols))
		for _, s := range f.COFFSymbols {
			log.Printf("\t%v", s)
		}
		// We need to relocate to start at *offset.
		// UEFI runs in page zero. I can't believe it.
		base := uintptr(*offset)
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
			if err := t.Write(addr, bb); err != nil {
				any(fmt.Sprintf("Can't write %d bytes of zero @ %#x for this section to process:", len(bb), addr, err))
				log.Fatalf("Can't write %d bytes of zero @ %#x for this section to process:", len(bb), addr, err)
			}
			if err := t.Write(addr, dat); err != nil {
				any(fmt.Sprintf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err))
				log.Fatalf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
			}
		}
		// For now we assume the entry point is the start of the first segment
		eip = base + uintptr(f.Sections[0].VirtualAddress)
	}
	trace.Debug = log.Printf
	// *start overrides it all.
	if *start != 0 {
		eip = uintptr(*start)
	}
	log.Printf("Start at %#x", eip)
	if err := trace.SetIPtr(t, uintptr(eip)); err != nil {
		log.Fatalf("Can't set IPtr to %#x: %v", eip, err)
	}
	log.Printf("IPtr is %#x, let's go.", eip)
	if err := trace.Params(t, uintptr(services.ImageHandle), uintptr(st)); err != nil {
		log.Fatalf("Setting params: %v", err)
	}
	if err := trace.Header(os.Stdout); err != nil {
		log.Fatal(err)
	}
	line++
	r, err := t.GetRegs()
	if err != nil {
		log.Fatalf("Could not get regs: %v", err)
	}
	if err := trace.Regs(os.Stdout, r); err != nil {
		log.Fatal(err)
	}
	p := r

	// Reserve space for structs that we will place into the memory.
	// For now, just drop the stack 1m and use that as a bump pointer.
	services.SetAllocator(uintptr(r.Rsp-0x100000), uintptr(r.Rsp))
	r.Rsp -= 0x100000

	log.Printf("Set stack to %#x", r.Rsp)
	if err := t.SetRegs(r); err != nil {
		log.Fatalf("Can't set stack to %#x: %v", dat, err)
	}
	//type Siginfo struct {
	//Signo  int // signal number
	//Errno  int // An errno value
	//Code   int // signal code
	//Trapno int // trap number that caused hardware-generated signal

	//Addr uintptr // Memory location which caused fault
	for e := range t.Events() {
		line++
		// Sometimes it fails with ESRCH but the process is there.
		// will need to restore this if we ever want ptrace back.
		i, err := t.GetSigInfo()
		for err != nil {
			log.Printf("%v,", err)
			i, err = t.GetSigInfo()
			any("Waiting for ^C, or hit return to try GetSigInfo again")
		}
		log.Printf("SIGNAL INFO: %#x", i)
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
		switch s {
		default:
			log.Printf("Can't do %#x(%v)", i.Signo, unix.SignalName(s))
			for {
				any("Waiting for ^C")
			}
		case unix.SIGSEGV:
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
			if err := segv(t, i, insn, r, segvasm); err != nil {
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

			if err := t.ClearSignals(); err != nil {
				//log.Printf("ClearSignal failed; %v", err)
				for {
					any("Waiting for ^C")
				}
			}
			//Debug(showone("", &r))
			any("move along")

		case unix.SIGTRAP:
		}

		if false {
			fmt.Printf("Event: %v,", e)
			i, err := t.GetSigInfo()
			if err != nil {
				log.Printf("%v,", err)
			} else {
				log.Printf("%v,", i)
			}
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
		if err := t.Run(); err != nil {
			log.Print(err)
		}
	}
}
