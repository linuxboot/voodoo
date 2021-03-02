// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"log"
	"syscall"

	"github.com/linuxboot/voodoo/ptrace"
	"github.com/linuxboot/voodoo/services"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

func segv(p *ptrace.Tracee, i *unix.SignalfdSiginfo, inst *x86asm.Inst, r *syscall.PtraceRegs, asm string) error {
	addr := uintptr(i.Addr)
	pc := r.Rip
	if r.Rip == 0x100000 {
		return io.EOF
	}
	nextpc := r.Rip + uint64(inst.Len)
	if pc < 0x200000 {
		var err error
		nextpc, err = p.Pop(r)
		if err != nil {
			return err
		}
		// TODO: adjust PC to be "the one before the one we popped"
		// but it's HARD.
		pc = nextpc
	}
	log.Printf("================={SEGV START FUNCTION @ %#x", addr)
	if err := services.Dispatch(&services.Fault{Proc: p, Info: i, Inst: inst, Regs: r, Asm: asm}); err != nil {
		return fmt.Errorf("Don't know what to do with %v: %v", ptrace.CallInfo(i, inst, r), err)
	}
	// Advance to the next instruction. This advance should only happen if the dispatch worked?
	r.Rip = nextpc
	defer log.Printf("===========} done SEGV @ %#x, rip was %#x, advance to %#x", addr, pc, r.Rip)
	return nil
}
