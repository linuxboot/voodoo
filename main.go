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
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"reflect"

	"github.com/linuxboot/voodoo/ptrace"
	"github.com/linuxboot/voodoo/services"
	"golang.org/x/sys/unix"
)

const ()

var ()

type msg func()

var (
	start      = flag.Uint64("start", 0, "starting address -- default is from PE/COFF but you can override")
	optional   = flag.Bool("optional", false, "Print optional registers")
	offset     = flag.String("offset", "0", "offset for objcopy")
	singlestep = flag.Bool("singlestep", false, "single step instructions")
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

	st, err := services.Base("systemtable")
	if err != nil {
		log.Fatal(err)
	}
	if *optional {
		ptrace.RegsPrint = ptrace.AllregsPrint
	}
	if *singlestep {
		step = any
	}
	f, err := ioutil.TempFile("", "voodoo")
	if err != nil {
		log.Fatal(err)
	}
	n := f.Name()
	o, err := exec.Command("objcopy", "--adjust-vma", *offset, "-O", "elf64-x86-64", a[0], n).CombinedOutput()
	if err != nil {
		log.Fatalf("objcopy to %s failed: %s %v", n, string(o), err)
	}
	f.Close()
	e, err := elf.Open(n)
	if err != nil {
		log.Fatal(err)
	}
	eip := uintptr(e.Entry)
	e.Close()

	t, err := ptrace.Exec(n, []string{n})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Process started with PID %d", t.PID())
	step()
	if err := t.SingleStep(); err != nil {
		log.Printf("First single step: %v", err)
	}
	step()
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
		// We need to relocate to start at 0x400000
		// UEFI runs in page zero. I can't believe it.
		base := uintptr(0x400000)
		for i, s := range f.Sections {
			fmt.Fprintf(os.Stderr, "Section %d", i)
			fmt.Fprintf(os.Stderr, show("\t", &s.SectionHeader))
			addr := base + uintptr(s.VirtualAddress)
			dat, err := s.Data()
			if err != nil {
				log.Fatalf("Can't get data for this section: %v", err)
			}
			if false {
				if err := t.Write(addr, dat); err != nil {
					any(fmt.Sprintf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err))
					log.Fatalf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
				}
			}
		}
		// For now we assume the entry point is the start of the first segment
		if false {
			eip = base + uintptr(f.Sections[0].VirtualAddress)
			if *start != 0 {
				eip = uintptr(*start)
			}
		}
	}
	log.Printf("Start at %#x", eip)
	if err := t.SetIPtr(uintptr(eip)); err != nil {
		log.Fatalf("Can't set IPtr to %#x: %v", eip, err)
	}
	log.Printf("IPtr is %#x, let's go.", eip)
	if err := t.Params(services.ImageHandle, st); err != nil {
		log.Fatalf("Setting params: %v", err)
	}
	if err := ptrace.Header(os.Stdout); err != nil {
		log.Fatal(err)
	}
	line++
	r, err := t.GetRegs()
	if err != nil {
		log.Fatalf("Could not get regs: %v", err)
	}
	if err := ptrace.Regs(os.Stdout, r); err != nil {
		log.Fatal(err)
	}
	p := r

	// Reserve space for structs that we will place into the memory.
	// For now, just drop the stack 1m and use that as a bump pointer.
	services.SetAllocator(uintptr(r.Rsp-0x100000), uintptr(r.Rsp))
	r.Rsp -= 0x100000

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
		if line%25 == 0 {
			ptrace.Header(os.Stdout)
		}
		line++
		// Sometimes it fails with ESRCH but the process is there.
		i, err := t.GetSiginfo()
		for err != nil {
			log.Printf("%v,", err)
			i, err = t.GetSiginfo()
			any("Waiting for ^C, or hit return to try GetSigInfo again")
		}
		log.Printf("SIGNAL INFO: %#x", i)
		s := unix.Signal(i.Signo)
		insn, r, err := t.Inst()
		if err != nil {
			log.Printf("Could not get regs: %v", err)
		}
		asm := ptrace.Asm(insn, r.Rip)
		fmt.Println(asm)
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
			if err := ptrace.Regs(os.Stdout, r); err != nil {
				log.Fatal(err)
			}
			if err := segv(t, i, insn, r, asm); err != nil {
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
			if err := t.ClearSignal(); err != nil {
				//log.Printf("ClearSignal failed; %v", err)
				for {
					any("Waiting for ^C")
				}
			}
			//showone(os.Stderr, "", &r)
			any("move along")

		case unix.SIGTRAP:
		}

		if false {
			fmt.Printf("Event: %v,", e)
			i, err := t.GetSiginfo()
			if err != nil {
				log.Printf("%v,", err)
			} else {
				log.Printf("%v,", i)
			}
		}
		if err := ptrace.RegDiff(os.Stdout, r, p); err != nil {
			log.Fatal(err)
		}
		p = r
		if err := t.SingleStep(); err != nil {
			log.Print(err)
		}
	}
}
