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

func segv(p trace.Trace, i *unix.SignalfdSiginfo, inst *x86asm.Inst, r *syscall.PtraceRegs, asm string) error {
	addr := uintptr(i.Addr)
	pc := r.Rip
	log.Printf("SEGV@%#x, rip %#x", addr, pc)
	if r.Rip < 0x1000 {
		log.Panicf("SEGV: BOGUS PC!")
	}
	nextpc := r.Rip + uint64(inst.Len)
	if pc >= uint64(services.ImageHandle) {
		var err error
		nextpc, err = trace.Pop(p, r)
		if err != nil {
			log.Printf("SEGV: return Pop failure")
			return err
		}
		// TODO: adjust PC to be "the one before the one we popped"
		// but it's HARD.
		pc = nextpc
	}
	log.Printf("================={SEGV START FUNCTION @ %#x", addr)
	if err := services.Dispatch(&services.Fault{Proc: p, Info: i, Inst: inst, Regs: r, Asm: asm}); err != nil {
		return fmt.Errorf("Don't know what to do with %v: %v", trace.CallInfo(i, inst, r), err)
	}
	// Advance to the next instruction. This advance should only happen if the dispatch worked?
	if false { // only for strace.
		r.Rip = nextpc
	}
	defer log.Printf("===========} done SEGV @ %#x, rip was %#x, advance to %#x", addr, pc, r.Rip)
	return nil
}
