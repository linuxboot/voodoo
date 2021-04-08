package services

import (
	"encoding/binary"
	"log"
	"os"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// TextIn implements Service
type TextIn struct {
	u  ServBase
	up ServPtr
}

var _ Service = &TextIn{}

func init() {
	RegisterCreator("textin", NewTextIn)
}

// NewTextIn returns a TextIn Service
func NewTextIn(tab []byte, u ServPtr) (Service, error) {
	Debug("textin services table u is %#x", u)
	base := int(u) & 0xffffff
	for p := range table.SimpleTextInServicesNames {
		x := base + int(p)
		r := uint64(p) + 0xff400000 + uint64(base)
		Debug("Install %#x at off %#x", r, x)
		binary.LittleEndian.PutUint64(tab[x:], uint64(r))
	}

	return &TextIn{u: ServBase(u.String()), up: u}, nil
}

// Base implements service.Base
func (t *TextIn) Base() ServBase {
	return t.u
}

// Base implements service.Base
func (t *TextIn) Ptr() ServPtr {
	return t.up
}

// Call implements service.Call
func (t *TextIn) Call(f *Fault) error {
	op := f.Op
	Debug("TextIn services: %v(%#x), arg type %T, args %v", table.SimpleTextInServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	f.Regs.Rax = uefi.EFI_SUCCESS
	switch op {
	case table.STInReset:
	case table.STInReadKeyStroke:
		var b [1]byte
		if _, err := os.Stdin.Read(b[:]); err != nil {
			log.Printf("StdinRead fails: %v", err)
		}
	case table.STInWaitForKey:
		var b [1]byte
		if _, err := os.Stdin.Read(b[:]); err != nil {
			log.Printf("StdinRead fails: %v", err)
		}
	default:
		log.Panicf("unsup textout Call: %#x", op)
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
