package services

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
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
// A BlockIO contains an pointer, not an embedded struct.
func NewBlockIO(tab []byte, u ServPtr) (Service, error) {
	Debug("New BlockIO ...")
	base := int(u) & 0xffffff
	// the media table is the next page after blockio.
	// Why page aligned? Might be useful, someday, to lock
	// things down.
	media := base + 0x1000
	for p := range table.BlockIOServiceNames {
		x := base + int(p)
		r := uint64(p) + 0xff400000 + uint64(base)
		switch p {
		// What's the right revision? Can't find it in the wall of data.
		case table.BlockIORevision:
			r = 1
		case table.BlockIOMedia:
			r = uint64(media)
		}
		binary.LittleEndian.PutUint64(tab[x:], uint64(r))
		Debug("blockio: Install %#x at off %#x", r, x)
	}

	var b = &bytes.Buffer{}
	if err := binary.Write(b, binary.LittleEndian, &table.BlockIOMediaInfo{
		MediaId:          0,
		RemovableMedia:   0,
		MediaPresent:     1,
		LogicalPartition: 1,
		ReadOnly:         0,
		WriteCaching:     0,
		BlockSize:        512,
		IoAlign:          0,
		LastBlock:        0,
	}); err != nil {
		return nil, fmt.Errorf("Can't encode memory: %v", err)
	}

	Debug("Install mediatable(%#x) at off %#x", b, media)

	return &BlockIO{u: u.Base(), up: u, media: ServPtr(media)}, nil
}

func (t *BlockIO) Aliases() []string {
	return nil
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

// OpenProtocol implements service.OpenProtocol
func (t *BlockIO) OpenProtocol(f *Fault, h *Handle, prot *dispatch, g guid.GUID, ptr uintptr, ah, ch *Handle, attr uintptr) error {
	log.Panicf("here we are")
	return fmt.Errorf("not yet")
}
