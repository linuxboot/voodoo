package services

import (
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// TextOut implements Service
type TextOut struct {
	u ServBase
}

func init() {
	RegisterCreator("textout", NewTextOut)
}

// NewTextOut returns a TextOut Service
func NewTextOut(u ServBase) (Service, error) {
	return &TextOut{u: u}, nil
}

// Base implements service.Base
func (t *TextOut) Base() ServBase {
	return t.u
}

// Call implements service.Call
func (t *TextOut) Call(f *Fault, op Func) error {
	log.Printf("TextOut services: %v(%#x), arg type %T, args %v", table.SimpleTextOutServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
