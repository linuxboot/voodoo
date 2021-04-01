// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"syscall"

	"github.com/linuxboot/voodoo/ptrace"
	"github.com/linuxboot/voodoo/services"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

func fromReg(r *syscall.PtraceRegs, arg x86asm.Arg) uint64 {

	switch arg {
	case x86asm.RSI:
		return r.Rsi
	case x86asm.RCX:
		return r.Rcx
	case x86asm.RDX:
		return r.Rdx
	case x86asm.RAX:
		return r.Rax
	case x86asm.R8:
		return r.R8
	}
	log.Panicf("fromReg: Can't handle %v", arg)
	return 0
}

func toReg(v uint64, r *syscall.PtraceRegs, arg x86asm.Arg) {
	switch arg {
	case x86asm.RSI:
		r.Rsi = v
	case x86asm.RCX:
		r.Rcx = v
	case x86asm.RDX:
		r.Rdx = v
	case x86asm.EDX:
		r.Rdx = v
	case x86asm.RAX:
		r.Rax = v
	case x86asm.R8:
		r.R8 = v
	}
	log.Panicf("toReg: Can't handle %v", arg)
}

func foldsegv(p *ptrace.Tracee, i *unix.SignalfdSiginfo, inst *x86asm.Inst, r *syscall.PtraceRegs, asm string) error {
	addr := uintptr(i.Addr)
	var dat [8]byte
	// Load data from source.
	dlen := inst.MemBytes
	log.Printf("foldsegv args: %v", inst.Args)
	switch val := inst.Args[1].(type) {
	case x86asm.Mem:
		log.Printf("mem")
		if err := p.Read(addr, dat[:]); err != nil {
			return fmt.Errorf("Reading %#x for %d bytes: %v", addr, dlen, err)
		}
	case x86asm.Imm:
		log.Printf("imm")
		log.Printf("%#x %#x", val, uint64(val))
		binary.LittleEndian.PutUint64(dat[:], uint64(val))
	case x86asm.Rel:
		log.Printf("rel")
		if err := p.Read(addr, dat[:]); err != nil {
			return fmt.Errorf("Reading %#x for %d bytes: %v", addr, dlen, err)
		}
	case x86asm.Reg:
		log.Printf("Reg")
		v := fromReg(r, inst.Args[1])
		binary.LittleEndian.PutUint64(dat[:], v)
	default:
		log.Panicf("Unknown type %T", inst.Args[0])
	}
	log.Printf("source value is %#x", dat)
	switch inst.Args[0].(type) {
	case x86asm.Mem:
		if err := p.Write(addr, dat[:dlen]); err != nil {
			return fmt.Errorf("Writing %#x for %d bytes: %v", addr, dlen, err)
		}
		log.Printf("mem")
	case x86asm.Imm:
		log.Panicf("%#x: Imm as dest is not possible", addr)
	case x86asm.Rel:
		if err := p.Write(addr, dat[:dlen]); err != nil {
			return fmt.Errorf("Reading %#x for %d bytes: %v", addr, dlen, err)
		}
		log.Printf("rel")
	case x86asm.Reg:
		// Get the current register value.
		old := fromReg(r, inst.Args[0])
		var bold [8]byte
		binary.LittleEndian.PutUint64(bold[:], old)
		copy(bold[:], dat[:dlen])
		old = binary.LittleEndian.Uint64(bold[:])
		toReg(old, r, inst.Args[0])
		log.Printf("Reg")
	default:
		log.Panicf("Unknown type %T", inst.Args[0])
	}
	return nil
}
func segv(p *ptrace.Tracee, i *unix.SignalfdSiginfo, inst *x86asm.Inst, r *syscall.PtraceRegs, asm string) error {
	addr := uintptr(i.Addr)
	log.Printf("================={SEGV START FUNCTION @ %#x", addr)
	if addr < 0x100000000 {
		log.Printf("%#x < %#x, fold it", addr, 0x100000000)
		r.Rip += uint64(inst.Len)
		return foldsegv(p, i, inst, r, asm)
	}
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
	if err := services.Dispatch(&services.Fault{Proc: p, Info: i, Inst: inst, Regs: r, Asm: asm}); err != nil {
		return fmt.Errorf("Don't know what to do with %v: %v", ptrace.CallInfo(i, inst, r), err)
	}
	// Advance to the next instruction. This advance should only happen if the dispatch worked?
	r.Rip = nextpc
	defer log.Printf("===========} done SEGV @ %#x, rip was %#x, advance to %#x", addr, pc, r.Rip)
	return nil
}
