package services

import (
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
func NewCollate(u ServPtr) (Service, error) {
	log.Printf("NewCollate %T %v", u, u)
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
	log.Printf("Collate services: %v(%#x), arg type %T, args %v", table.CollateServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	f.Regs.Rax = uefi.EFI_SUCCESS
	switch op {
	default:
		log.Panicf("unsup collate Call: %#x", op)
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Load implements service.Load
func (r *Collate) Load(f *Fault) error {
	f.Regs.Rax = uefi.EFI_SUCCESS
	op := f.Op
	t, ok := table.CollateServicesNames[uint64(op)]
	if !ok {
		log.Panicf("unsupported Collate Load of %#x", op)
	}
	ret := uintptr(op) + uintptr(r.up)
	switch op {
	default:
	}
	log.Printf("Collate Load services: %v(%#x), arg type %T, args %v return %#x", t, op, f.Inst.Args, f.Inst.Args, ret)
	if err := retval(f, ret); err != nil {
		log.Panic(err)
	}
	return nil
}

// Store implements service.Store
func (r *Collate) Store(f *Fault) error {
	f.Regs.Rax = uefi.EFI_SUCCESS
	op := f.Op
	log.Printf("Collate Store services: %v(%#x), arg type %T, args %v", table.CollateServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported Collate Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
