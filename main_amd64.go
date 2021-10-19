// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"syscall"

	"github.com/linuxboot/voodoo/services"
	"github.com/linuxboot/voodoo/trace"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

// halt handles the halt case. Things differ a bit from segv.
// First off, the pc will be one off, having been incrementd. Other issues apply as well.
func halt(p trace.Trace, i *unix.SignalfdSiginfo, inst *x86asm.Inst, r *syscall.PtraceRegs, asm string) error {
	addr := uintptr(i.Addr)
	nextpc := r.Rip
	pc := r.Rip - 1
	Debug("HALT@%#x, rip %#x", addr, pc)
	if pc == 0xfff0 {
		log.Panicf("HALT: system reset")
	}

	r.Rip = pc
	Debug("================={HALT START FUNCTION @ %#x", addr)
	if err := services.Dispatch(&services.Fault{Proc: p, Info: i, Inst: inst, Regs: r, Asm: asm}); err != nil {
		return fmt.Errorf("Don't know what to do with %v: %v", trace.CallInfo(i, inst, r), err)
	}
	// Advance to the next instruction. This advance should only happen if the dispatch worked?
	r.Rip = nextpc
	defer Debug("===========} done HALT @ %#x, rip was %#x, advance to %#x", addr, pc, r.Rip)
	return nil
}

func checkConsole(i *x86asm.Inst, r *syscall.PtraceRegs, asm string) {
	if asm != "out %al,(%dx)" {
		return
	}
	c := uint8(r.Rax)
	if *debug {
		Debug("CONSOUT: %c", c)
	} else if *handleConsoleIO {
		fmt.Printf("%c", c)
	}

}

// this is not great, but will have to do for now.
// Never anticipated multi-architecture.
func setupRegs(r *syscall.PtraceRegs) uintptr {
	r.Eflags |= 0x100
	return uintptr(r.Rsp)
}
func setStack(r *syscall.PtraceRegs, sp uintptr) {
	r.Rsp = uint64(sp)
}
func getStack(r *syscall.PtraceRegs) uintptr {
	return uintptr(r.Rsp)
}
func setPC(r *syscall.PtraceRegs, pc uintptr) {
	r.Rip = uint64(pc)
}
