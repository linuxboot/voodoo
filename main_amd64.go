// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"syscall"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/ptrace"
	"github.com/linuxboot/voodoo/table"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

type rprint struct {
	name   string
	format string
	extra  string
}

var (
	genregsprint = []rprint{
		{name: "Rip", format: "%#x"},
		{name: "R15", format: "%016x"},
		{name: "R14", format: "%016x"},
		{name: "R13", format: "%016x"},
		{name: "R12", format: "%016x"},
		{name: "Rbp", format: "%016x"},
		{name: "Rbx", format: "%016x"},
		{name: "R11", format: "%016x"},
		{name: "R10", format: "%016x"},
		{name: "R9", format: "%016x", extra: "/A3"},
		{name: "R8", format: "%016x", extra: "/A2"},
		{name: "Rax", format: "%016x"},
		{name: "Rcx", format: "%016x", extra: "/A0"},
		{name: "Rdx", format: "%016x", extra: "/A1"},
		{name: "Rsi", format: "%016x"},
		{name: "Rdi", format: "%016x"},
		{name: "Orig_rax", format: "%016x"},
		{name: "Eflags", format: "%08x"},
		{name: "Rsp", format: "%016x"},
	}
	allregsprint = append(regsprint,
		[]rprint{
			{name: "Fs_base", format: "%016x"},
			{name: "Gs_base", format: "%016x"},
			{name: "Cs", format: "%04x"},
			{name: "Ds", format: "%04x"},
			{name: "Es", format: "%04x"},
			{name: "Fs", format: "%04x"},
			{name: "Gs", format: "%04x"},
			{name: "Ss", format: "%04x"},
		}...)
	regsprint = genregsprint
)

func EfiErr(e EFIError) uintptr {
	return uintptr(1<<63) | uintptr(e)
}

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
	l += fmt.Sprintf("(%#x, %#x, %#x, %#x)", r.Rcx, r.Rdx, r.R8, r.R9)
	return l
}

func args(t *ptrace.Tracee, r *syscall.PtraceRegs, nargs int) []uintptr {
	sp := uintptr(r.Rsp)
	switch nargs {
	case 6:
		w1, _ := t.ReadWord(sp + 0x20)
		w2, _ := t.ReadWord(sp + 0x28)
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx), uintptr(r.R8), uintptr(r.R9), uintptr(w1), uintptr(w2)}
	case 5:
		w1, _ := t.ReadWord(sp + 0x20)
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx), uintptr(r.R8), uintptr(r.R9), uintptr(w1)}
	case 4:
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx), uintptr(r.R8), uintptr(r.R9)}
	case 3:
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx), uintptr(r.R8)}
	case 2:
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx)}
	case 1:
		return []uintptr{uintptr(r.Rcx)}
	}
	return []uintptr{}
}

func pointer(inst *x86asm.Inst, r *syscall.PtraceRegs, arg int) (uintptr, error) {
	m := inst.Args[arg].(x86asm.Mem)
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
	log.Printf("ARG[%d] %q m is %#x", inst.Args[arg], m)
	b, err := GetReg(r, m.Base)
	if err != nil {
		any("FUCKED BASE")
		return 0, fmt.Errorf("Can't get Base reg %v in %v", m.Base, m)
	}
	addr := *b + uint64(m.Disp)
	x, err := GetReg(r, m.Index)
	if err == nil {
		addr += uint64(m.Scale) * (*x)
	}
	//if v, ok := inst.Args[0].(*x86asm.Mem); ok {
	log.Printf("computed addr is %#x", addr)
	return uintptr(addr), nil
}

func segv(p *ptrace.Tracee, i *unix.SignalfdSiginfo) error {
	addr := i.Addr
	// We may be here with a bogus PC, in the case of a call.
	// That means we have args in the usual places.
	// We need to the args, etc., pop the stack to get return address,
	// bla bla bla.
	// We first need to see if it's a call that got us here.
	// So if the inst() fails, we'll need to look at (rsp) and get the inst from there.
	// For now, we're gonna hack it out. If the failing addr is in the range
	// of funcs we assume function call.
	/*	if addr >= StartFuncs && addr < EndFuncs {
			// Assume it's a call. We can switch on the addr. We're going to want to pop the
			// stack when done.
			op := addr & 0xffff
			log.Printf("functions: %v(%#x), arg type %T, args %v", table.RuntimeServicesNames[op], op, inst.Args, inst.Args)
			switch op {
			case table.STOutputString:
				args := args(p, &r, 6)
				log.Printf("StOutputString args %#x", args)
				r.Rax = EFI_SUCCESS
				if err := p.SetRegs(r); err != nil {
					return err
				}
				return nil
			default:
				log.Printf("conout op opcode %#x addr %v: unknonw opcode", op, addr)
				r.Rax = EFI_SUCCESS
				if err := p.SetRegs(r); err != nil {
					return err
				}
				return nil
			}
		}

		}*/
	inst, pc, err := inst(p)
	if err != nil {
		return err
	}
	r, err := p.GetRegs()
	if err != nil {
		return err
	}
	log.Printf("Segv: addr %#x: %s", addr, showone("\t", &r))
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
		op := addr & 0xffff
		n, ok := table.SystemTableNames[op]
		if !ok {
			return fmt.Errorf("No system table entry for offset %#x: %s\n", op, l)
		}
		log.Printf("System table: %#x, %s", op, n.N)
		// code expects to return a value of a thing, or call that thing.
		// So consistent.
		switch inst.Args[0] {
		case x86asm.RCX:
			r.Rcx = n.Val
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		case x86asm.RAX:
			r.Rax = n.Val
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		case x86asm.R8:
			r.R8 = n.Val
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		default:
			return fmt.Errorf("Can't handle dest %v", inst.Args[0])
		}
	}
	if (addr >= LoadedImage) && (addr <= LoadedImage+0x10000) {
		l := fmt.Sprintf("%#x, %s[", pc, InfoString(i))
		for _, a := range inst.Args {
			l += fmt.Sprintf("%v,", a)
		}
		l += "]"
		op := addr & 0xffff
		n, ok := table.LoadedImageTableNames[op]
		if !ok {
			return fmt.Errorf("No loaded image entry for offset %#x: %s\n", op, l)
		}
		log.Printf("loaded image table: %#x, %s", op, n.N)
		switch inst.Args[0] {
		case x86asm.EDX:
			r.Rdx = n.Val
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		case x86asm.RDX:
			r.Rdx = n.Val
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		case x86asm.RCX:
			r.Rcx = n.Val
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		case x86asm.RAX:
			r.Rax = n.Val
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		default:
			return fmt.Errorf("Can't handle dest %v", inst.Args[0])
		}
	}
	if (addr >= Boot) && (addr <= Boot+0x10000) {
		// No matter what happpens, move to the next one.
		r.Rip += uint64(inst.Len)
		if err := p.SetRegs(r); err != nil {
			return err
		}
		op := addr & 0xffff
		log.Printf("Boot services: %s(%#x), arg type %T, args %v", bootServicesNames[int(op)], op, inst.Args, inst.Args)
		switch op {
		case AllocatePool:
			// Status = gBS->AllocatePool (EfiBootServicesData, sizeof (EXAMPLE_DEVICE), (VOID **)&Device);
			args := args(p, &r, 3)
			// ignore arg 0 for now.
			log.Printf("AllocatePool: %d bytes", args[1])
			var bb [8]byte
			binary.LittleEndian.PutUint64(bb[:], uint64(dat))
			if err := p.Write(args[2], bb[:]); err != nil {
				return fmt.Errorf("Can't write %d bytes to %#x: %v", len(bb), dat, err)
			}
			dat += args[1]
			return nil
		case FreePool:
			// Status = gBS->FreePool (Device);
			args := args(p, &r, 1)
			// Free? Forget it.
			log.Printf("FreePool: %#x", args[0])
			return nil
		case LocateHandle:
			// EFI_STATUS LocateHandle (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID *Protocol OPTIONAL, IN VOID *SearchKey OPTIONAL,IN OUT UINTN *NoHandles,  OUT EFI_HANDLE **Buffer);
			args := args(p, &r, 5)
			no := args[3]
			var bb [8]byte
			// just fail.
			if err := p.Write(no, bb[:]); err != nil {
				return fmt.Errorf("Can't write %d bytes to %#x: %v", len(bb), dat, err)
			}
			return nil
		case HandleProtocol:
			// There. All on one line. Not 7. So, UEFI, did that really hurt so much?
			// typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface);

			// The arguments are rcx, rdx, r9
			args := args(p, &r, 3)
			var g guid.GUID
			if err := p.Read(args[1], g[:]); err != nil {
				return fmt.Errorf("Can't read guid at #%x, err %v", args[1], err)
			}
			log.Printf("HandleProtocol: GUID %s", g)
			if err := Srv(p, &g, args...); err != nil {
				return fmt.Errorf("Can't handle HandleProtocol: %s: %v", callinfo(i, inst, r), err)
			}
			return nil
		case PCHandleProtocol:
			// There. All on one line. Not 7. So, UEFI, did that really hurt so much?
			// typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface);

			// The arguments are rcx, rdx, r9
			args := args(p, &r, 3)
			var g guid.GUID
			if err := p.Read(args[1], g[:]); err != nil {
				return fmt.Errorf("Can't read guid at #%x, err %v", args[1], err)
			}
			log.Printf("PCHandleProtocol: GUID %s", g)
			if err := Srv(p, &g, args...); err != nil {
				return fmt.Errorf("Can't handle HandleProtocol: %s: %v", callinfo(i, inst, r), err)
			}
			return nil
		case ConnectController:
			// The arguments are rcx, rdx, r9, r8
			args := args(p, &r, 4)
			log.Printf("ConnectController: %#x", args)
			// Just pretend it worked.
			return nil
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
	if (addr >= Runtime) && (addr <= Runtime+0x10000) {
		// No matter what happpens, move to the next one.
		r.Rip += uint64(inst.Len)
		if err := p.SetRegs(r); err != nil {
			return err
		}
		op := addr & 0xffff
		log.Printf("Runtime services: %v(%#x), arg type %T, args %v", table.RuntimeServicesNames[op], op, inst.Args, inst.Args)
		switch op {
		case table.RTGetVariable:
			args := args(p, &r, 5)
			log.Printf("table.RTGetVariable args %#x", args)
			ptr := args[0]
			n, err := p.ReadStupidString(ptr)
			if err != nil {
				return fmt.Errorf("Can't read StupidString at #%x, err %v", ptr, err)
			}
			var g guid.GUID
			if err := p.Read(args[1], g[:]); err != nil {
				return fmt.Errorf("Can't read guid at #%x, err %v", args[1], err)
			}
			log.Printf("PCHandleProtocol: find %s %s", n, g)
			v, err := ReadVariable(n, g)
			if err != nil {
				r.Rax = EFI_NOT_FOUND
				if err := p.SetRegs(r); err != nil {
					return err
				}
			}
			log.Printf("%s:%s: v is %v", n, g, v)
			r.Rax = EFI_SUCCESS
			return nil
		default:
			return fmt.Errorf("opcode %#x addr %v: unknonw opcode", op, addr)
		}
	}
	if (addr >= ConOut) && (addr <= ConOut+0x10000) {
		l := fmt.Sprintf("%#x, %s[", pc, InfoString(i))
		for _, a := range inst.Args {
			l += fmt.Sprintf("%v,", a)
		}
		l += "]"
		op := addr & 0xfff
		// pretend it's a deref
		var n uint64
		if op <= table.STMode {
			n = STOut + op
		}

		log.Printf("ConOut table: %#x, %#x", op, n)
		// code expects to return a value of a thing, or call that thing.
		// So consistent.
		switch inst.Args[0] {
		case x86asm.RCX:
			r.Rcx = n
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		case x86asm.RAX:
			r.Rax = n
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		case x86asm.R8:
			r.R8 = n
			r.Rip += uint64(inst.Len)
			if err := p.SetRegs(r); err != nil {
				return err
			}
			return nil
		default:
			return fmt.Errorf("ConOut Can't handle dest %v", inst.Args[0])
		}
	}
	return fmt.Errorf("Don't know what to do with %v", callinfo(i, inst, r))
}
