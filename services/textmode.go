package services

import (
	"encoding/binary"
	"log"

	"github.com/linuxboot/voodoo/table"
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
func NewTextMode(tab []byte, u ServPtr) (Service, error) {
	log.Printf("NewTextMode %#x", u)
	base := int(u) & 0xffffff
	for p := range table.SimpleTextModeServicesNames {
		x := base + int(p)
		r := uint64(p) + 0xff400000 + uint64(base)
		log.Printf("Install %#x at off %#x", r, x)
		binary.LittleEndian.PutUint64(tab[x:], uint64(r))
	}

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
