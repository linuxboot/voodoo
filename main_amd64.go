// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"syscall"

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

// GetReg gets a register value from the Tracee.
// This code does not do any ptrace calls to get registers.
// It returns a pointer so the register can be read and modified.
func GetReg(r *syscall.PtraceRegs, reg x86asm.Reg) (*uint64, error) {
	log.Printf("GetReg %s", reg)
	switch reg {
	case x86asm.AL:
	case x86asm.CL:
	case x86asm.DL:
	case x86asm.BL:
	case x86asm.AH:
	case x86asm.CH:
	case x86asm.DH:
	case x86asm.BH:
	case x86asm.SPB:
	case x86asm.BPB:
	case x86asm.SIB:
	case x86asm.DIB:
	case x86asm.R8B:
	case x86asm.R9B:
	case x86asm.R10B:
	case x86asm.R11B:
	case x86asm.R12B:
	case x86asm.R13B:
	case x86asm.R14B:
	case x86asm.R15B:

	// 16-bit
	case x86asm.AX:
	case x86asm.CX:
	case x86asm.DX:
	case x86asm.BX:
	case x86asm.SP:
	case x86asm.BP:
	case x86asm.SI:
	case x86asm.DI:
	case x86asm.R8W:
	case x86asm.R9W:
	case x86asm.R10W:
	case x86asm.R11W:
	case x86asm.R12W:
	case x86asm.R13W:
	case x86asm.R14W:
	case x86asm.R15W:

	// 32-bit
	case x86asm.EAX:
	case x86asm.ECX:
	case x86asm.EDX:
	case x86asm.EBX:
	case x86asm.ESP:
	case x86asm.EBP:
	case x86asm.ESI:
	case x86asm.EDI:
	case x86asm.R8L:
	case x86asm.R9L:
	case x86asm.R10L:
	case x86asm.R11L:
	case x86asm.R12L:
	case x86asm.R13L:
	case x86asm.R14L:
	case x86asm.R15L:

	// 64-bit
	case x86asm.RAX:
		return &r.Rax, nil
	case x86asm.RCX:
		return &r.Rcx, nil
	case x86asm.RDX:
		return &r.Rdx, nil
	case x86asm.RBX:
		return &r.Rbx, nil
	case x86asm.RSP:
		return &r.Rsp, nil
	case x86asm.RBP:
		return &r.Rbp, nil
	case x86asm.RSI:
		return &r.Rsi, nil
	case x86asm.RDI:
		return &r.Rdi, nil
	case x86asm.R8:
		return &r.R8, nil
	case x86asm.R9:
		return &r.R9, nil
	case x86asm.R10:
		return &r.R10, nil
	case x86asm.R11:
		return &r.R11, nil
	case x86asm.R12:
		return &r.R12, nil
	case x86asm.R13:
		return &r.R13, nil
	case x86asm.R14:
		return &r.R14, nil
	case x86asm.R15:
		return &r.R15, nil
	case x86asm.RIP:
		return &r.Rip, nil
	// Instruction pointer.
	case x86asm.IP: // 16-bit:
	case x86asm.EIP: // 32-bit:

	// 387 floating point registers.
	case x86asm.F0:
	case x86asm.F1:
	case x86asm.F2:
	case x86asm.F3:
	case x86asm.F4:
	case x86asm.F5:
	case x86asm.F6:
	case x86asm.F7:

	// MMX registers.
	case x86asm.M0:
	case x86asm.M1:
	case x86asm.M2:
	case x86asm.M3:
	case x86asm.M4:
	case x86asm.M5:
	case x86asm.M6:
	case x86asm.M7:

	// XMM registers.
	case x86asm.X0:
	case x86asm.X1:
	case x86asm.X2:
	case x86asm.X3:
	case x86asm.X4:
	case x86asm.X5:
	case x86asm.X6:
	case x86asm.X7:
	case x86asm.X8:
	case x86asm.X9:
	case x86asm.X10:
	case x86asm.X11:
	case x86asm.X12:
	case x86asm.X13:
	case x86asm.X14:
	case x86asm.X15:

	// Segment registers.
	case x86asm.ES:
	case x86asm.CS:
	case x86asm.SS:
	case x86asm.DS:
	case x86asm.FS:
	case x86asm.GS:

	// System registers.
	case x86asm.GDTR:
	case x86asm.IDTR:
	case x86asm.LDTR:
	case x86asm.MSW:
	case x86asm.TASK:

	// Control registers.
	case x86asm.CR0:
	case x86asm.CR1:
	case x86asm.CR2:
	case x86asm.CR3:
	case x86asm.CR4:
	case x86asm.CR5:
	case x86asm.CR6:
	case x86asm.CR7:
	case x86asm.CR8:
	case x86asm.CR9:
	case x86asm.CR10:
	case x86asm.CR11:
	case x86asm.CR12:
	case x86asm.CR13:
	case x86asm.CR14:
	case x86asm.CR15:

	// Debug registers.
	case x86asm.DR0:
	case x86asm.DR1:
	case x86asm.DR2:
	case x86asm.DR3:
	case x86asm.DR4:
	case x86asm.DR5:
	case x86asm.DR6:
	case x86asm.DR7:
	case x86asm.DR8:
	case x86asm.DR9:
	case x86asm.DR10:
	case x86asm.DR11:
	case x86asm.DR12:
	case x86asm.DR13:
	case x86asm.DR14:
	case x86asm.DR15:

	// Task registers.
	case x86asm.TR0:
	case x86asm.TR1:
	case x86asm.TR2:
	case x86asm.TR3:
	case x86asm.TR4:
	case x86asm.TR5:
	case x86asm.TR6:
	case x86asm.TR7:
	}

	return nil, fmt.Errorf("Can get %v", reg)
}

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

func callinfo(s *unix.SignalfdSiginfo, inst *x86asm.Inst, r syscall.PtraceRegs) string {
	l := fmt.Sprintf("%s, %s[", show("", &r), InfoString(s))
	for _, a := range inst.Args {
		l += fmt.Sprintf("%v,", a)
	}
	l += "]"
	return l
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
		// No matter what happpens, move to the next one.
		r.Rip += uint64(inst.Len)
		if err := p.SetRegs(r); err != nil {
			return err
		}
		op := addr & 0xffff
		op -= BootServicesOffset
		//log.Printf("%s(%#x), arg type %T, args %#x", bootServicesNames[int(op)], op, inst.Args, inst.Args)
		switch op {
		case HandleProtocol:
			return fmt.Errorf("Can't handle HandleProtocol: %s", callinfo(i, inst, r))
			// we think this is a print function? no idea
		case 0xfffe:
			arg0, err := GetReg(&r, x86asm.RDX)
			if err != nil {
				return fmt.Errorf("Can't get RDX: %v", err)
			}
			any("go get it")
			// idiot UEFI and idiot wchar_t
			arg := uintptr(*arg0)
			for {
				var dat [2]byte
				if err := p.Read(arg, dat[:]); err != nil {
					return fmt.Errorf("Can't read data at #%x, err %v", addr, err)
				}
				if dat[0] == 0 && dat[1] == 0 {
					break
				}
				fmt.Printf("%#02x %c,", dat, dat[0])
				arg++
			}
			// This code is right for getting an arbitrary Mem out.
			// It's wrong for 0xf8, whoops. Leave it here
			// for reference.
		case 0xffff:
			m := inst.Args[0].(x86asm.Mem)
			// A Mem is a memory reference.
			// The general form is Segment:[Base+Scale*Index+Disp].
			/*
				type Mem struct {
					Segment Reg
					Base    Reg
					Scale   uint8
					Index   Reg
					Disp    int64
				}
			*/
			log.Printf("ARG[0] %q m is %#x", inst.Args[0], m)
			b, err := GetReg(&r, m.Base)
			if err != nil {
				any("FUCKED BASE")
				return fmt.Errorf("Can't get Base reg %v in %v", m.Base, m)
			}
			addr := *b + uint64(m.Disp)
			x, err := GetReg(&r, m.Index)
			if err == nil {
				addr += uint64(m.Scale) * (*x)
			}
			//if v, ok := inst.Args[0].(*x86asm.Mem); ok {
			log.Printf("computed addr is %#x", addr)
			any("go get it")
			var dat [16]byte
			if err := p.Read(uintptr(addr), dat[:]); err != nil {
				return fmt.Errorf("Can't read data at #%x, err %v", addr, err)
			}
			log.Printf("dat at %#x is %#x", addr, dat)

			//return nil
			//}
			//return fmt.Errorf("Wrong type of 0xf8? %T but should be %T", inst.Args[0], x86asm.Mem)
			return nil
		default:
			return fmt.Errorf("opcode %#x addr %v: unknonw opcode", op, addr)
		}
	}
	return fmt.Errorf("Don't know what to do with %v", callinfo(i, inst, r))
}
