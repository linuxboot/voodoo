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
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/sys/unix"
)

// d42006e0 	brk	#0x37
const tosSentinal = 0xd42006e0d42006e0

// halt handles the halt case. Things differ a bit from segv.
// First off, the pc will be one off, having been incrementd. Other issues apply as well.
func halt(p trace.Trace, i *unix.SignalfdSiginfo, inst *arm64asm.Inst, r *syscall.PtraceRegs, asm string) error {
	addr := uintptr(i.Addr)
	nextpc := r.Pc
	pc := r.Pc - 1
	Debug("HALT@%#x, rip %#x", addr, pc)
	if pc == 0 {
		log.Panicf("HALT: system reset")
	}

	r.Pc = pc
	Debug("================={HALT START FUNCTION @ %#x", addr)
	if err := services.Dispatch(&services.Fault{Proc: p, Info: i, Inst: inst, Regs: r, Asm: asm}); err != nil {
		return fmt.Errorf("Don't know what to do with %v: %v", trace.CallInfo(i, inst, r), err)
	}
	// Advance to the next instruction. This advance should only happen if the dispatch worked?
	r.Pc = nextpc
	defer Debug("===========} done HALT @ %#x, rip was %#x, advance to %#x", addr, pc, r.Pc)
	return nil
}

func checkConsole(i *arm64asm.Inst, r *syscall.PtraceRegs, asm string) {
	c := '#'
	if *debug {
		Debug("CONSOUT: %c", c)
	} else if *handleConsoleIO {
		log.Panicf("checkconsole: no")
	}

}

// this is not great, but will have to do for now.
// Never anticipated multi-architecture.
func setupRegs(r *syscall.PtraceRegs) uintptr {
	return uintptr(r.Sp)
}
func setStack(r *syscall.PtraceRegs, sp uintptr) {
	r.Sp = uint64(sp)
}
func getStack(r *syscall.PtraceRegs) uintptr {
	return uintptr(r.Sp)
}
func setPC(r *syscall.PtraceRegs, pc uintptr) {
	r.Pc = uint64(pc)
}
