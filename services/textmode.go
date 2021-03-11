package services

import (
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// TextMode implements Service
type TextMode struct {
	u         ServBase
	up        ServPtr
	max       uint32
	mode      uint32
	attribute uint32
	col       uint32
	row       uint32
	vis       uint32
}

var _ Service = &TextMode{}

func init() {
	RegisterCreator("textoutmode", NewTextMode)
}

// NewTextMode returns a TextMode Service
func NewTextMode(u ServPtr) (Service, error) {
	log.Printf("NewTextMode %#x", u)
	return &TextMode{u: u.Base(), up: u}, nil
}

// Base implements service.Base
func (t *TextMode) Base() ServBase {
	return t.u
}

// Ptr implements service.Ptr
func (t *TextMode) Ptr() ServPtr {
	return t.up
}

// Call implements service.Call
// we don't care about textout mode. It's stupid.
// just ignore and move on.
func (t *TextMode) Call(f *Fault) error {
	log.Panicf("No TextMode Calls allowed")
	return nil
}

// Load implements service.Load
func (t *TextMode) Load(f *Fault) error {
	op := f.Op
	f.Regs.Rax = uefi.EFI_SUCCESS
	tm, ok := table.SimpleTextModeServicesNames[uint64(op)]
	if !ok {
		log.Panicf("unsupported TextMode Load of %#x", op)
	}
	ret := uintptr(op) + uintptr(t.up)
	log.Printf("TextMode services: %v(%#x), arg type %T, args %v", tm, op, f.Inst.Args, f.Inst.Args)
	if err := retval(f, ret); err != nil {
		log.Panic(err)
	}
	return nil
}

// Store implements service.Store
func (t *TextMode) Store(f *Fault) error {
	op := f.Op
	log.Printf("TextMode services: %v(%#x), arg type %T, args %v", table.SimpleTextModeServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported TextMode Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
