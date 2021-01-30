// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"

	"github.com/linuxboot/voodoo/ptrace"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

type rprint struct {
	name   string
	format string
}

var (
	genregsprint = []rprint{
		{"Rip", "%#x"},
		{"R15", "%016x"},
		{"R14", "%016x"},
		{"R13", "%016x"},
		{"R12", "%016x"},
		{"Rbp", "%016x"},
		{"Rbx", "%016x"},
		{"R11", "%016x"},
		{"R10", "%016x"},
		{"R9", "%016x"},
		{"R8", "%016x"},
		{"Rax", "%016x"},
		{"Rcx", "%016x"},
		{"Rdx", "%016x"},
		{"Rsi", "%016x"},
		{"Rdi", "%016x"},
		{"Orig_rax", "%016x"},
		{"Eflags", "%08x"},
		{"Rsp", "%016x"},
	}
	allregsprint = append(regsprint,
		[]rprint{
			{"Fs_base", "%016x"},
			{"Gs_base", "%016x"},
			{"Cs", "%04x"},
			{"Ds", "%04x"},
			{"Es", "%04x"},
			{"Fs", "%04x"},
			{"Gs", "%04x"},
			{"Ss", "%04x"},
		}...)
	regsprint = genregsprint
)

// Set the params in %rcx, %rdx
func params(p *ptrace.Tracee, ImageHandle, SystemTable uint64) error {
	r, err := p.GetRegs()
	if err != nil {
		return err
	}
	r.Rcx = ImageHandle
	r.Rdx = SystemTable
	return p.SetRegs(r)
}

func inst(p *ptrace.Tracee) (*x86asm.Inst, uintptr, error) {
	pc, err := p.GetIPtr()
	if err != nil {
		return nil, 0, fmt.Errorf("Could not get pc: %v", err)
	}
	// We know the PC; grab a bunch of bytes there, then decode and print
	insn := make([]byte, 16)
	if err := p.Read(pc, insn); err != nil {
		log.Printf("Can' read PC at #%x, err %v", pc, err)
		return nil, 0, err
	}
	d, err := x86asm.Decode(insn, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("Can't decode %#02x: %v", insn, err)
	}
	return &d, pc, nil
}

func disasm(t *ptrace.Tracee) (string, error) {
	d, pc, err := inst(t)
	if err != nil {
		return "", fmt.Errorf("Can't decode %#02x: %v", d, err)
	}
	return x86asm.GNUSyntax(*d, uint64(pc), nil), nil
}

// InfoString prints a nice format of a ptrace.SigInfo
func InfoString(i *unix.SignalfdSiginfo) string {
	return fmt.Sprintf("%s Errno %d Code %#x Trapno %d Addr %#x", unix.SignalName(unix.Signal(i.Signo)), i.Errno, i.Code, i.Trapno, i.Addr)
}

func segv(p *ptrace.Tracee, i *unix.SignalfdSiginfo) error {
	// The pattern is a destination register.
	// This is sleazy and easy, so do it.
	addr := i.Addr
	inst, pc, err := inst(p)
	if err != nil {
		return err
	}
	r, err := p.GetRegs()
	if err != nil {
		return err
	}
	if (addr >= ImageHandle) && (addr <= ImageHandleEnd) {
		l := fmt.Sprintf("%#x, %s[", pc, InfoString(i))
		for _, a := range inst.Args {
			l += fmt.Sprintf("%s,", a.String())
		}
		l += "]"
		return fmt.Errorf("ImageHandle error, %v", l)
	}
	if (addr >= SystemTable) && (addr <= SystemTableEnd) {
		l := fmt.Sprintf("%#x, %s[", pc, InfoString(i))
		for _, a := range inst.Args {
			l += fmt.Sprintf("%v,", a)
		}
		l += "]"
		switch inst.Args[0] {
		case x86asm.RCX:
			r.Rcx = uint64(addr) + 0x10000
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		case x86asm.RAX:
			r.Rax = uint64(addr) + 0x10000
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		default:
			return fmt.Errorf("Can't handle dest %v", inst.Args[0])
		}
	}
	if (addr >= SystemTableEnd) && (addr <= SystemTableEnd+0x10000) {
		switch addr & 0xffff {
		case 0xf8:
			var b [8]byte
			err := p.Read(uintptr(x86asm.RDX), b[:])
			if err != nil {
				return fmt.Errorf("Reading %#x: %v", r.Rdx, err)
			}

			fmt.Printf("%#x", b)
			return nil
		default:
			return fmt.Errorf("Don't know what to do with %v", addr)
		}
	}
	l := fmt.Sprintf("%#x, %s[", pc, InfoString(i))
	for _, a := range inst.Args {
		l += fmt.Sprintf("%v,", a)
	}
	l += "]"
	return fmt.Errorf("Don't know what to do with %v", l)
}
