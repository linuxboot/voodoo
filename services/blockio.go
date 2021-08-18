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
	u               ServBase
	up              ServPtr
	media           ServPtr
	devicepathproto ServPtr
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
	// TODO: if we ever figure out what we want here,
	// there needs to be Marshaler for this nonsense
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
	// put the ABSOLUTE address into dpp.
	// 0xffxx0000, since we'll be returning this to the bootloader.
	dpp := ServPtr(int(u) + 0x2000)
	// and now for the device path. This stuff is *SO BAD*
	// This is from the spec.
	// Table 32-SCSI device path examples
	for i, b := range []byte{
		//Byte offset	Byte length	Data	Description
		0x00: 0x02, //Generic Device Path Header - Type ACPI Device Path
		0x01: 0x01, //Sub type - ACPI Device Path
		0x02: 0x0C, //Length - 0x0C bytes
		0x04: 0x41, //_HID PNP0A03 - 0x41D0 represents a compressed string
		0x05: 0xD0, // 'PNP' and is in the low-order bytes.
		0x06: 0x0A, //
		0x07: 0x03, //
		// UID @ 8 for 4 bytes of 0s
		// UID @ 8 for 4 bytes of 0s
		// UID @ 8 for 4 bytes of 0s
		// UID @ 8 for 4 bytes of 0s
		0x0C: 0x01, //Generic Device Path Header - Type Hardware Device Path
		0x0D: 0x01, //Sub type - PCI
		0x0E: 0x06, //Length - 0x06 bytes
		0x10: 0x07, //PCI Function
		0x11: 0x00, //PCI Device
		0x12: 0xFF, //Generic Device Path Header - Type End of Hardware Device Path
		0x13: 0xFF, //Sub type - End of Entire Device Path
		0x14: 0x04, //Length - 0x04 bytes
		0x15: 0x00,
		0x16: 0x00,
		0x17: 0x00,
	} {
		tab[int(index(dpp))+i] = b
	}

	// Now create a handle for this device.
	h := newHandle()
	serv := &BlockIO{u: u.Base(), up: u, media: ServPtr(media), devicepathproto: dpp}
	h.PutService(uefi.BlockIOGUID, serv, u)
	pathserv := &DevicePath{u: dpp.Base(), up: dpp}
	h.PutService(uefi.DevicePathGUID, pathserv, dpp)
	return serv, nil
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
func (t *BlockIO) OpenProtocol(f *Fault, h *Handle, g guid.GUID, ptr uintptr, ah, ch *Handle, attr uintptr) (*dispatch, error) {
	log.Panicf("here we are")
	return nil, fmt.Errorf("not yet")
}
