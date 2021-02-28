package services

import (
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// TextOut implements Service
type TextOut struct {
	u ServBase
	t *TextMode
}

func init() {
	RegisterCreator("textout", NewTextOut)
}

// NewTextOut returns a TextOut Service
func NewTextOut(u ServBase) (Service, error) {
	// We need to get to the TextOutMode.
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
	case table.STOutMode:
		panic("stoutmode")
	default:
		panic("unsup textout")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
