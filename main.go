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
	debug      = flag.Bool("debug", false, "Enable debug prints")
	dryrun     = flag.Bool("dryrun", false, "set up but don't run")
	regpath    = flag.String("registerfile", "", "file to log registers to, in .csv format")
	handleConsoleIO = flag.Bool("doIO", false, "break glass -- enable this to check IO exits for console")
	regfile    *os.File
	Debug      = func(string, ...interface{}) {}
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
	if *debug {
		Debug = log.Printf
	}
	trace.SetDebug(Debug)
	services.Debug = Debug
	if len(*regpath) > 0 {
		f, err := os.OpenFile(*regpath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		regfile = f
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
	if err := loadPE(v, a, r, Debug); err != nil {
		log.Fatal(err)
	}

	st, h, err := services.NewSystemtable(v.Tab())
	if err != nil {
		log.Fatal(err)
	}

	Debug("params are %#08x %#08x", h, st)
	trace.Params(r, uintptr(h), uintptr(st))
	// bogus params to see if we can manages a segv
	//r.Rcx = uint64(imageHandle)
	//r.Rdx = uint64(systemTable)
	r.Eflags |= 0x100

	if err := v.SetRegs(r); err != nil {
		log.Fatalf("GetRegs: got %v, want nil", err)
	}

	// Reserve space for DXE data.
	services.SetAllocBase(0x40000000)

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
	if *dryrun {
		log.Panic("dry run")
	}

	p := r
	for {
		line++
		Debug("------------------------------------------------------------------->> %d: ", line)
		// DOUBLE CHECK that run fails to produce an event!
		go func() {
			for err := v.Run(); err != nil; err = v.Run() {
				log.Printf("Run: got %v, want nil", err)
			}
		}()
		ev := <-v.Events()
		s := unix.Signal(ev.Signo)
		Debug("\t %d: Event %#x, trap %d", line, ev, ev.Trapno)
		insn, r, g, err := trace.Inst(v)
		if err != nil {
			if err == io.EOF {
				fmt.Println("\n===:DXE Exits!")
				os.Exit(0)
			}
			log.Fatalf("Could not get regs: %v", err)
		}

		// TODO: add a test for bogus RIP. In a VM, anything goes, however.

		switch {
		case ev.Trapno == kvm.ExitDebug:
		case ev.Trapno == kvm.ExitHlt:
			// This ONLY happens on an exit OR calling a UEFI function.
			if *debug {
				if err := trace.Regs(os.Stdout, r); err != nil {
					log.Fatal(err)
				}
			}
			haltasm := trace.Asm(insn, r.Rip)
			if err := halt(v, &ev, insn, r, haltasm); err != nil {
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

			step("returned from halt, set regs, move along")

		case ev.Trapno == kvm.ExitIo:
			checkConsole(insn, r, g)
		default:
			log.Printf("Trapno: got %#x", ev.Trapno)
			if ev.Trapno == kvm.ExitShutdown {
				i, r, g, err := trace.Inst(v)
				if err != nil {
					log.Fatalf("Inst: got %v, want nil", err)
				}
				cpc, err := trace.Pop(v, r)
				if err != nil {
					log.Printf("Could not pop stack to get caller pc")
					cpc = 0xdeadbeef
				}
				log.Fatalf("Shutdown from %#x! [%v, %v, %q, %v]", cpc, i, showone("", r), g, err)
			}
		}
		r, err = v.GetRegs()
		if err != nil {
			log.Fatalf("GetRegs: got %v, want nil", err)
		}
		if regfile != nil {
			if err := trace.RegDiff(regfile, r, p); err != nil {
				log.Fatal(err)
			}
		}
		p = r
		//log.Printf("REGS: %s", show("", r))
		//		e := ev.cpu.VMRun.String()
		//		log.Printf("IP is %#x, exit %s", r.Rip, e)

		i, r, g, err := trace.Inst(v)
		if err != nil {
			log.Fatalf("Inst: got %v, want nil", err)
		}
		Debug("Inst returns %v, %v, %q, %v", i, r, g, err)
	}
	log.Printf("Exit: Rsp is %#x", r.Rsp)
}
