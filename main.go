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

	"github.com/tfogal/ptrace"
)

type msg func()

func any(f ...msg) {
	var b [1]byte
	for _, ff := range f {
		ff()
	}
	log.Printf("hit the any key")
	os.Stdin.Read(b[:])
}

func showone(w io.Writer, indent string, in interface{}) {
	s := reflect.ValueOf(in).Elem()
	typeOfT := s.Type()

	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		fmt.Printf(indent+"\t%s %s = %v\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
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
	for i, s := range f.Sections {
		fmt.Fprintf(os.Stderr, "Section %d", i)
		show(os.Stderr, "\t", &s.SectionHeader)
		addr := s.VirtualAddress
		dat, err := s.Data()
		if err != nil {
			log.Fatalf("Can't get data for this section: %v", err)
		}
		if err := t.Write(uintptr(addr), dat); err != nil {
			f := func() {
				log.Printf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
			}
			any(f)
			log.Fatalf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
		}
	}
	// For now we assume the entry point is the start of the first segment
	eip := f.Sections[0].VirtualAddress
	if err := t.SetIPtr(uintptr(eip)); err != nil {
		log.Fatalf("Can't set IPtr to %#x: %v", eip, err)
	}
	log.Printf("IPtr is %#x, let's go.", eip)
	for e := range t.Events() {
		fmt.Printf("Event: %v, ", e)
		r, err := t.GetRegs()
		if err != nil {
			log.Printf("Could not get regs: %v", err)
		}
		show(os.Stderr, "", &r)
		pc, err := t.GetIPtr()
		if err != nil {
			log.Printf("Could not get pc: %v", err)
		}
		fmt.Printf("PC %#x\n", pc)
		if err := t.SingleStep(); err != nil {
			log.Print(err)
		}
	}
}
