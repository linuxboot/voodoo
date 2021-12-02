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
	lr := r.Regs[kvm.ELREL]
	pc := r.Pc
	Debug("================={MMIO START FUNCTION @ %#x, rip %#x, LR %#x", i.Addr, r.Pc, lr)
	if pc == 0x200 {
		log.Panicf("HALT: system reset")
	}
	if pc < uint64(services.ProtocolBase) {
		log.Panicf("MMIO outside RPC area: %#x", r.Pc)
	}

	// The mmio instruction is the one after the one we use for RPC.
	// This needs a bit of fixin' I suppose.
	// one option is that services.Dispatch could blow the low 3 bits clear,
	// but that loses some useful error check.
	// r.Pc -= 4
	// The i.Addr is a constant we put in to cause an MMIO. Ignore it.
	i.Addr = r.Regs[8]
	if err := services.Dispatch(&services.Fault{Proc: p, Info: i, Inst: inst, Regs: r, Asm: asm}); err != nil {
		return fmt.Errorf("Dispatch returned an error: %v: CallInfo: %v", err, trace.CallInfo(i, inst, r))
	}
	// Stay on the MMIO. Kernel then advances the instruction.
	//r.Pc = pc
	defer Debug("===========} done MMIO @ %#x, rip was %#x, resume at %#x", i.Addr, pc, r.Pc)
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
