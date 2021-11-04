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
	"github.com/linuxboot/voodoo/trace/kvm"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/sys/unix"
)

// d42006e0 	brk	#0x37
const tosSentinal = 0xd42006e0d42006e0

func halt(p trace.Trace, i *unix.SignalfdSiginfo, inst *arm64asm.Inst, r *syscall.PtraceRegs, asm string) error {
	panic("halt")
}

// mmiohandles the mmio case.
// The return PC will be in the LR. We hope.
func mmio(p trace.Trace, i *unix.SignalfdSiginfo, inst *arm64asm.Inst, r *syscall.PtraceRegs, asm string) error {
	addr := uintptr(r.Pc)
	nextpc := r.Regs[kvm.ELREL]
	pc := uint64(uint32(addr))
	Debug("MMIO@%#x, rip %#x", addr, pc)
	if pc == 0x200 {
		log.Panicf("HALT: system reset")
	}

	// The mmio instruction is the one after the one we use for RPC.
	// This needs a bit of fixin' I suppose. 
	// one option is that services.Dispatch could blow the low 3 bits clear, 
	// but that loses some useful error check.
	r.Pc -= 4
	// The i.Addr is a constant we put in to cause an MMIO. Ignore it.
	i.Addr = r.Pc
	Debug("================={MMIO START FUNCTION @ %#x", i.Addr)
	if err := services.Dispatch(&services.Fault{Proc: p, Info: i, Inst: inst, Regs: r, Asm: asm}); err != nil {
		return fmt.Errorf("Don't know what to do with %v: %v", trace.CallInfo(i, inst, r), err)
	}
	// Advance to the next instruction. This advance should only happen if the dispatch worked?
	r.Pc = nextpc
	defer Debug("===========} done MMIO @ %#x, rip was %#x, advance to %#x", addr, pc, r.Pc)
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
