package services

import (
	"log"

	"github.com/linuxboot/voodoo/ptrace"
	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// TextOut implements Service
type TextOut struct {
	u ServBase
	t ServBase
}

func init() {
	RegisterCreator("textout", NewTextOut)
}

// NewTextOut returns a TextOut Service
func NewTextOut(u ServBase) (Service, error) {
	// We need to get to the TextOutMode.
	tm, err := Base("textoutmode")
	if err != nil {
		return nil, err
	}
	return &TextOut{u: u, t: ServBase(tm)}, nil
}

// Base implements service.Base
func (t *TextOut) Base() ServBase {
	return t.u
}

// Call implements service.Call
func (t *TextOut) Call(f *Fault) error {
	op := f.Op
	log.Printf("TextOut services: %v(%#x), arg type %T, args %v", table.SimpleTextOutServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	f.Regs.Rax = uefi.EFI_SUCCESS
	switch op {
	case table.STOutOutputString:
		args := ptrace.Args(f.Proc, f.Regs, 6)
		log.Printf("StOutOutputString args %#x", args)
		n, err := f.Proc.ReadStupidString(uintptr(args[1]))
		if err != nil {
			return err
		}
		log.Printf("stupid is %q", n)
		if err := f.Proc.SetRegs(f.Regs); err != nil {
			return err
		}
		return nil
	case table.STOutSetAttribute:
		log.Printf("Fuck STOutSetAttribute")
	case table.STOutMode:
		if err := retval(f, uintptr(t.t)); err != nil {
			log.Panic(err)
		}
	default:
		panic("unsup textout")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Load implements service.Load
func (r *TextOut) Load(f *Fault) error {
	op := f.Op
	log.Printf("TextOut Load services: %v(%#x), arg type %T, args %v", table.SimpleTextOutServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)

	switch op {
	default:
		log.Panic("unsupported TextOut load")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Store implements service.Store
func (r *TextOut) Store(f *Fault) error {
	op := f.Op
	log.Printf("TextOut Store services: %v(%#x), arg type %T, args %v", table.SimpleTextOutServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported TextOut Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
