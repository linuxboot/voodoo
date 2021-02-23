// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"syscall"

	"github.com/linuxboot/voodoo/ptrace"
	"github.com/linuxboot/voodoo/services"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

func segv(p *ptrace.Tracee, i *unix.SignalfdSiginfo, inst *x86asm.Inst, r *syscall.PtraceRegs) error {
	addr := uintptr(i.Addr)
	pc := r.Rip
	log.Printf("================={SEGV START FUNCTION @ %#x", addr)
	if err := services.Dispatch(&services.Fault{Proc: p, Info: i, Inst: inst, Regs: r}); err != nil {
		return fmt.Errorf("Don't know what to do with %v: %v", ptrace.CallInfo(i, inst, r), err)
	}
	// Advance to the next instruction. This advance should only happen if the dispatch worked?
	r.Rip += uint64(inst.Len)
	defer log.Printf("===========} done SEGV @ %#x, rip was %#x, advance to %#x", addr, pc, r.Rip)
	return nil
}
