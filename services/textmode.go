package services

import (
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// TextMode implements Service
type TextMode struct {
	u ServBase
}

func init() {
	RegisterCreator("textoutmode", NewTextMode)
}

// NewTextMode returns a TextMode Service
func NewTextMode(u ServBase) (Service, error) {
	return &TextMode{u: u}, nil
}

// Base implements service.Base
func (t *TextMode) Base() ServBase {
	return t.u
}

// Call implements service.Call
// we don't care about textout mode. It's stupid.
func (t *TextMode) Call(f *Fault, op Func) error {
	log.Printf("TextMode services: %v(%#x), arg type %T, args %v", table.SimpleTextModeServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		f.Regs.Rax = uefi.EFI_SUCCESS
	}
	return nil
}
