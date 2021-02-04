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
	"syscall"

	"github.com/linuxboot/voodoo/ptrace"
	"golang.org/x/sys/unix"
)

const (
	// ImageHandle is
	ImageHandle = 0x110000
	// ImageHandleEnd is
	ImageHandleEnd = 0x120000
	// SystemTable is
	SystemTable = 0x120000
	// SystemTableEnd isn
	SystemTableEnd = 0x130000
	// FuncPointer is
	FuncPointer = 0x140000
)

type msg func()

var (
	start      = flag.Uint64("start", 0, "starting address -- default is from PE/COFF but you can override")
	optional   = flag.Bool("optional", false, "Print optional registers")
	offset     = flag.String("offset", "0", "offset for objcopy")
	singlestep = flag.Bool("singlestep", false, "single step instructions")
	step       = func(...string) {}
	mem        = flag.Uint64("bump", 0x80000000, "where to put dynamic stuff for UEFI")
)

func any(f ...string) {
	var b [1]byte
	for _, ff := range f {
		log.Println(ff)
	}
	log.Printf("hit the any key")
	os.Stdin.Read(b[:])
}

func header(w io.Writer) error {
	var l string
	for _, r := range regsprint {
		l += fmt.Sprintf("%s,", r.name)
	}
	_, err := fmt.Fprint(w, l+"\n")
	return err
}

// print the regs
func regs(w io.Writer, r *syscall.PtraceRegs) error {
	rr := reflect.ValueOf(r).Elem()
	var l string
	for _, rp := range regsprint {
		rf := rr.FieldByName(rp.name)
		l += fmt.Sprintf(rp.format+",", rf.Interface())
	}
	_, err := fmt.Fprint(w, l)
	return err
}

// Only print things that differ.
func regdiff(w io.Writer, r, p *syscall.PtraceRegs) error {
	rr := reflect.ValueOf(r).Elem()
	pp := reflect.ValueOf(p).Elem()

	var l string
	for _, rp := range regsprint {
		rf := rr.FieldByName(rp.name)
		pf := pp.FieldByName(rp.name)
		rv := fmt.Sprintf(rp.format, rf.Interface())
		pv := fmt.Sprintf(rp.format, pf.Interface())
		if rv != pv {
			l += rv
		}
		l += ","
	}
	_, err := fmt.Fprint(w, l)
	return err
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
	if *optional {
		regsprint = allregsprint
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
	if err := params(t, ImageHandle, SystemTable); err != nil {
		log.Fatalf("Setting params: %v", err)
	}
	if err := header(os.Stdout); err != nil {
		log.Fatal(err)
	}
	r, err := t.GetRegs()
	if err != nil {
		log.Printf("Could not get regs: %v", err)
	}
	if err := regs(os.Stderr, &r); err != nil {
		log.Fatal(err)
	}
	p := r
	//type Siginfo struct {
	//Signo  int // signal number
	//Errno  int // An errno value
	//Code   int // signal code
	//Trapno int // trap number that caused hardware-generated signal

	//Addr uintptr // Memory location which caused fault
	for e := range t.Events() {
		// Sometimes it fails with ESRCH but the process is there.
		i, err := t.GetSiginfo()
		for err != nil {
			log.Printf("%v,", err)
			i, err = t.GetSiginfo()
			any("Waiting for ^C, or hit return to try GetSigInfo again")
		}
		log.Printf("%v", i)
		s := unix.Signal(i.Signo)
		r, err := t.GetRegs()
		if err != nil {
			log.Printf("Could not get regs: %v", err)
		}
		switch s {
		default:
			log.Printf("Can't do %#x(%v)", i.Signo, unix.SignalName(s))
			for {
				any("Waiting for ^C")
			}
		case unix.SIGSEGV:
			//showone(os.Stderr, "", &r)
			//any(fmt.Sprintf("Handle the segv at %#x", i.Addr))
			if err := segv(t, i); err != nil {
				//showone(os.Stderr, "", &r)
				log.Printf("Can't do %#x(%v): %v", i.Signo, unix.SignalName(s), err)
				for {
					any("Waiting for ^C")
				}
			}
			if err := t.ClearSignal(); err != nil {
				//log.Printf("ClearSignal failed; %v", err)
				for {
					any("Waiting for ^C")
				}
			}
			//showone(os.Stderr, "", &r)
			//any("move along")

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
		if err := regdiff(os.Stderr, &r, &p); err != nil {
			log.Fatal(err)
		}
		p = r
		if s, err := disasm(t); err != nil {
			log.Fatal(err)
		} else {
			fmt.Println(s)
		}
		step()
		if err := t.SingleStep(); err != nil {
			log.Print(err)
		}
	}
}
