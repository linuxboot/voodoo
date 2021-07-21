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
	Debug("register BlockIO ...")
	RegisterGUIDCreator(table.BlockIOGUID, NewBlockIO)
}

// NewBlockIO returns a BlockIO Service
func NewBlockIO(tab []byte, u ServPtr) (Service, error) {
	Debug("New BlockIO ...")
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
	Debug("BlockIO services: %v(%#x), arg type %T, args %v", table.BlockIOServiceNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	f.Regs.Rax = uefi.EFI_SUCCESS
	switch op {
	case table.BlockIORevision:
	case table.BlockIOMedia:
	case table.BlockIOReset:
	case table.BlockIOReadBlocks:
	case table.BlockIOWriteBlocks:
	case table.BlockIOFlushBlocks:
	}
	log.Panicf("unsupported BlockIO Call: %#x", op)
	f.Regs.Rax = uefi.EFI_UNSUPPORTED
	return nil
}
