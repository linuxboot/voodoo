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
	"syscall"

	"github.com/tfogal/ptrace"
	"golang.org/x/arch/x86/x86asm"
)

type msg func()

var (
	start = flag.Uint64("start", 0, "starting address -- default is from PE/COFF but you can override")
)

func any(f ...msg) {
	var b [1]byte
	for _, ff := range f {
		ff()
	}
	log.Printf("hit the any key")
	os.Stdin.Read(b[:])
}

func header(w io.Writer, r *syscall.PtraceRegs) error {
	s := reflect.ValueOf(r).Elem()
	typeOfT := s.Type()

	var l string
	for i := 0; i < s.NumField(); i++ {
		l += fmt.Sprintf("%s,", typeOfT.Field(i).Name)
	}
	_, err := fmt.Fprint(w, l)
	return err
}

func regs(w io.Writer, r *syscall.PtraceRegs) error {
	s := reflect.ValueOf(r).Elem()

	var l string
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		l += fmt.Sprintf("%#x,", f.Interface())
	}
	_, err := fmt.Fprint(w, l)
	return err
}
func showone(w io.Writer, indent string, in interface{}) {
	s := reflect.ValueOf(in).Elem()
	typeOfT := s.Type()

	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		fmt.Printf(indent+"\t%s %s = %#x\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
	}

}
func show(w io.Writer, indent string, l ...interface{}) {
	for _, i := range l {
		showone(w, indent, i)
	}
}

func main() {
	flag.Parse()
	a := flag.Args()
	if len(a) != 1 {
		log.Fatal("arg count")
	}
	t, err := ptrace.Exec("a", []string{"a"})
	if err != nil {
		log.Fatal(err)
	}
	any()
	if err := t.SingleStep(); err != nil {
		log.Printf("First single step: %v", err)
	}
	any()
	// Now fill it up
	f, err := pe.Open(flag.Args()[0])
	if err != nil {
		log.Fatal(err)
	}
	show(os.Stderr, "", &f.FileHeader)
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
		show(os.Stderr, "\t", &s.SectionHeader)
		addr := base + uintptr(s.VirtualAddress)
		dat, err := s.Data()
		if err != nil {
			log.Fatalf("Can't get data for this section: %v", err)
		}
		if false {
			if err := t.Write(addr, dat); err != nil {
				f := func() {
					log.Printf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
				}
				any(f)
				log.Fatalf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
			}
		}
	}
	// For now we assume the entry point is the start of the first segment
	eip := base + uintptr(f.Sections[0].VirtualAddress)
	if *start != 0 {
		eip = uintptr(*start)
	}
	log.Printf("Start at %#x", eip)
	if err := t.SetIPtr(uintptr(eip)); err != nil {
		log.Fatalf("Can't set IPtr to %#x: %v", eip, err)
	}
	log.Printf("IPtr is %#x, let's go.", eip)
	if err := header(os.Stdout, &syscall.PtraceRegs{}); err != nil {
		log.Fatal(err)
	}
	for e := range t.Events() {
		if false {
			fmt.Printf("Event: %v, ", e)
		}
		r, err := t.GetRegs()
		if err != nil {
			log.Printf("Could not get regs: %v", err)
		}
		if err := regs(os.Stderr, &r); err != nil {
			log.Fatal(err)
		}
		pc, err := t.GetIPtr()
		if err != nil {
			log.Printf("Could not get pc: %v", err)
		}
		// We know the PC; grab a bunch of bytes there, then decode and print
		insn := make([]byte, 16)
		if err := t.Read(pc, insn); err != nil {
			log.Printf("Can' read PC at #%x, err %v", pc, err)
			continue
		}
		d, err := x86asm.Decode(insn, 64)
		if err != nil {
			log.Printf("Can't decode %#02x: %v", insn, err)
			continue
		}
		fmt.Println(x86asm.GNUSyntax(d, uint64(pc), nil))
		any()
		if err := t.SingleStep(); err != nil {
			log.Print(err)
		}
	}
}
