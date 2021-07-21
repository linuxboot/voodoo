package services

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// BlockIO implements Service
type BlockIO struct {
	u     ServBase
	up    ServPtr
	media ServPtr
}

var _ Service = &BlockIO{}

func init() {
	Debug("register BlockIO ...")
	RegisterGUIDCreator(table.BlockIOGUID, NewBlockIO)
}

// NewBlockIO returns a BlockIO Service
func NewBlockIO(tab []byte, u ServPtr) (Service, error) {
	Debug("New BlockIO ...")
	base := int(u) & 0xffffff
	mtable := base + 0x1000
	Debug("Install media table for %#x at %#x", base, mtable)
	var bb = [8]byte{}
	binary.LittleEndian.PutUint64(bb[:], mtable)
	if err := f.Proc.Write(base+table.BlockIOMedia, bb[:]); err != nil {
		return fmt.Errorf("Can't write %d bytes to %#x: %v", len(bb), dat, err)
	}

	binary.LittleEndian.PutUint64(base+table.BlockIOMedia, mtable)
	var b = &bytes.Buffer{}
	if err := binary.Write(b, binary.LittleEndian, &BlockIOMedia{
		MediaId:          0xdeadbeef,
		RemovableMedia:   1,
		MediaPresent:     1,
		LogicalPartition: 0,
		ReadOnly:         1,
		WriteCaching:     0,
		BlockSize:        4096,
		IoAlign:          4096,
		LastBlock:        1048576,
	}); err != nil {
		return nil, fmt.Errorf("Can't encode memory: %v", err)
	}
	if err := f.Proc.Write(mtable, b[:]); err != nil {
		return fmt.Errorf("Can't write %d bytes to %#x: %v", len(bb), mtable, err)
	}

	return &BlockIO{u: u.Base(), up: u, media: mtable}, nil
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
