package services

import (
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// TextMode implements Service
type TextMode struct {
	u         ServBase
	max       uint32
	mode      uint32
	attribute uint32
	col       uint32
	row       uint32
	vis       uint32
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
// just ignore and move on.
func (t *TextMode) Call(f *Fault, op Func) error {
	log.Printf("TextMode services: %v(%#x), arg type %T, args %v", table.SimpleTextModeServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	f.Regs.Rax = uefi.EFI_SUCCESS
	switch op {
	case table.STModeMaxMode:
	case table.STModeMode:
	case table.STModeAttribute:
	case table.STModeCursorColumn:
	case table.STModeCursorRow:
	case table.STModeCursorVisible:
	default:
		log.Panicf("textmode: what?")
	}
	return nil
}
