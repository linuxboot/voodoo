// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,amd64

package main

import (
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
	a := flag.Args()[0]
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
	if err := loadPE(v, a, r, log.Printf); err != nil {
		log.Fatal(err)
	}

//	r.Eflags |= 0x100

	st, err := services.Base("systemtable")
	if err != nil {
		log.Fatal(err)
	}

	trace.Params(r, uintptr(services.ImageHandle), uintptr(st))
	// bogus params to see if we can manages a segv
	//r.Rcx = uint64(imageHandle)
	//r.Rdx = uint64(systemTable)

	if err := v.SetRegs(r); err != nil {
		log.Fatalf("GetRegs: got %v, want nil", err)
	}

	// Reserve space for structs that we will place into the memory.
	// We'll try putting it in the bios area.
	services.SetAllocator(0xff000000, 0xff100000)

	trace.Debug = log.Printf

	efisp := r.Rsp
	// When it does the final return, it has to halt.
	// Put a halt on top of stack, and point top of stack to it.
	if err := trace.WriteWord(v, uintptr(efisp), 0xf4f4f4f4f4f4f4f4); err != nil {
		log.Fatalf("Writing halts at %#x: got %v, want nil", efisp, err)
	}

	sp := uint64(r.Rsp)
	efisp -= 8
	if err := trace.WriteWord(v, uintptr(efisp), sp); err != nil {
		log.Fatalf("Writing stack %#x at %#x: got %v, want nil", efisp, efisp-8, err)
	}
	trace.Debug = log.Printf

	for {
		line++
		go func() {
			if err := v.Run(); err != nil {
				log.Fatalf("Run: got %v, want nil", err)
			}
		}()
		ev := <-v.Events()
		s := unix.Signal(ev.Signo)
		log.Printf("------------------------------------------------------------------->> %d: Event %#x, trap %d", line, ev, ev.Trapno)
		insn, r, g, err := trace.Inst(v)
		if err != nil {
			if err == io.EOF {
				fmt.Println("\n===:DXE Exits!")
				os.Exit(0)
			}
			log.Fatalf("Could not get regs: %v", err)
		}

		switch {
		case ev.Trapno == kvm.ExitDebug:
		case ev.Trapno == kvm.ExitMmio:
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
			if err := segv(v, &ev, insn, r, segvasm); err != nil {
				if err == io.EOF {
					fmt.Println("\n===:DXE Exits!")
					os.Exit(0)
				}
				//showone(os.Stderr, "", &r)
				log.Printf("Can't do %#x(%v): %v", ev.Signo, unix.SignalName(s), err)
				for {
					any("Waiting for ^C")
				}
			}
			// The handlers will always change, at least, eip, so just blindly set them
			// back. TODO: see if we need more granularity.
			if err := v.SetRegs(r); err != nil {
				log.Fatalf("Can't set stack to %#x: %v", dat, err)
			}

			// if err := t.ReArm(); err != nil {
			// 	//log.Printf("ClearSignal failed; %v", err)
			// 	for {
			// 		any("Waiting for ^C")
			// 	}
			// }
			//Debug(showone("", &r))
			any("move along")

		default:
			log.Printf("Trapno: got %#x", ev.Trapno)
		}
		r, err = v.GetRegs()
		if err != nil {
			log.Fatalf("GetRegs: got %v, want nil", err)
		}
		log.Printf("REGS: %s", show("", r))
		//		e := ev.cpu.VMRun.String()
		//		log.Printf("IP is %#x, exit %s", r.Rip, e)

		i, r, g, err := trace.Inst(v)
		if err != nil {
			log.Fatalf("Inst: got %v, want nil", err)
		}
		log.Printf("Inst returns %v, %v, %q, %v", i, r, g, err)
	}
	log.Printf("Rsp is %#x", r.Rsp)
	// we "just know" for now.
	if r.Rsp != 0x70c4ff70 {
		log.Fatalf("SP: got %#x, want %#x", r.Rsp, 0x70c4ff70)
	}
}
