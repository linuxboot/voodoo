package services

import (
	"encoding/binary"
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// Collate implements Service
type Collate struct {
	u  ServBase
	up ServPtr
}

func init() {
	RegisterGUIDCreator("1D85CD7F-F43D-11D2-9A0C-0090273FC14D", NewCollate)
}

// NewCollate returns a Collate Service
func NewCollate(tab []byte, u ServPtr) (Service, error) {
	Debug("New Collate ...")
	base := int(u) & 0xffffff

	for p := range table.CollateServicesNames {
		x := base + int(p)
		r := uint64(p) + 0xff400000 + uint64(base)
		binary.LittleEndian.PutUint64(tab[x:], uint64(r))
		Debug("collate: Install %v %#x at off %#x", p, r, x)
	}

	return &Collate{u: u.Base(), up: u}, nil
}

// Base implements service.Base
func (t *Collate) Base() ServBase {
	return t.u
}

// Base implements service.Ptr
func (c *Collate) Ptr() ServPtr {
	return c.up
}

// Call implements service.Call
func (t *Collate) Call(f *Fault) error {
	op := f.Op
	Debug("Collate services: %v(%#x), arg type %T, args %v", table.CollateServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	f.Regs.Rax = uefi.EFI_SUCCESS
	switch op {
	default:
		log.Panicf("unsup collate Call: %#x", op)
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
