package services

import (
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// BlockIO implements Service
type BlockIO struct {
	u  ServBase
	up ServPtr
}

var _ Service = &BlockIO{}

func init() {
	RegisterGUIDCreator(table.BlockIOGUID, NewBlockIO)
}

// NewBlockIO returns a BlockIO Service
func NewBlockIO(tab []byte, u ServPtr) (Service, error) {
	return &BlockIO{u: u.Base(), up: u}, nil
}

// Base implements service.Base
func (t *BlockIO) Base() ServBase {
	return t.u
}

// Ptr implements service.Ptr
func (t *BlockIO) Ptr() ServPtr {
	return t.up
}

// Call implements service.Call
func (t *BlockIO) Call(f *Fault) error {
	op := f.Op
	log.Printf("BlockIO services: %v(%#x), arg type %T, args %v", table.BlockIOServiceNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	f.Regs.Rax = uefi.EFI_SUCCESS
	switch op {
	default:
		log.Panicf("unsup textout Call: %#x", op)
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Load implements service.Load
func (r *BlockIO) Load(f *Fault) error {
	f.Regs.Rax = uefi.EFI_SUCCESS
	op := f.Op
	t, ok := table.BlockIOServiceNames[uint64(op)]
	if !ok {
		log.Panicf("unsupported BlockIO Load of %#x", op)
	}
	switch op {
	default:
		log.Panicf("unsup BlockIO Load: %v %#x", t, op)
	}
	return nil
}

// Store implements service.Store
func (r *BlockIO) Store(f *Fault) error {
	f.Regs.Rax = uefi.EFI_SUCCESS
	op := f.Op
	log.Printf("BlockIO Store services: %v(%#x), arg type %T, args %v", table.BlockIOServiceNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported BlockIO Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
