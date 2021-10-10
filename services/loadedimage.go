package services

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// This protocol should be loaded FIRST.
// It should be at the base, currently 0xff000000
const LoadedImageProtocol = "5B1B31A1-9562-11D2-8E3F-00A0C969723B"

// LoadedImage implements Service
type LoadedImage struct {
	u  ServBase
	up ServPtr
}

var aliases = []string{LoadedImageProtocol}

func init() {
	RegisterCreator(LoadedImageProtocol, NewLoadedImage)
}

// NewLoadedImage returns a LoadedImage Service
func NewLoadedImage(tab []byte, u ServPtr) (Service, error) {
	Debug("New LoadedImage ...")
	base := int(u) & 0xffffff
	// Idiot code usually can't handled a NULL pointer.
	// Since we own this 64k region we can just point at the next page
	// and call it a day.
	// This stuff is just such shit.
	// see 3.9 UEFI device paths
	// we'll marshall later when we know what to do.
	// anyway ...
	// of *Fault, h, and, good news, GNUEFI and the docs disagree on the
	// end type. UEFI is hopeless.
	fp := []byte{0x7f, // hardware
		0xff, //the last one. 0xff in the docs.
		2, 0, // LE length
		0, 0, // dev, function.
	}
	fpx := 0x100 + 0xff400000 + uint64(base)
	Debug("LoadedImage base at index %#08x; fp[%#02x] at index %#08x", base, fp, fpx)
	if false {
		copy(tab[fpx:], fp)
	}

	for p := range table.LoadedImageTableNames {
		x := base + int(p)
		r := uint64(p) + 0xff400000 + uint64(base)
		switch p {
		case table.LIRevision:
		case table.LIParentHandle:
		case table.LISystemTable:
		case table.LIDeviceHandle:
		case table.LIFilePath:
			r = 0xff000000 + fpx
		case table.LIReserved:
		case table.LILoadOptionsSize:
		case table.LILoadOptions:
		case table.LIImageBase:
		case table.LIImageSize:
		case table.LIImageCodeType:
		case table.LIImageDataType:
		case table.LIUnload:
		}
		binary.LittleEndian.PutUint64(tab[x:], uint64(r))
		Debug("LoadedImage: Install %#x at off %#x", r, x)
	}

	return &LoadedImage{u: u.Base(), up: u}, nil
}

// Aliases implements Aliases
func (l *LoadedImage) Aliases() []string {
	return aliases
}

// Base implements service.Base
func (l *LoadedImage) Base() ServBase {
	return l.u
}

// Base implements service.Ptr
func (l *LoadedImage) Ptr() ServPtr {
	return l.up
}

// Call implements service.Call
func (l *LoadedImage) Call(f *Fault) error {
	op := f.Op
	Debug("LoadedImage Call: %#x, arg type %T, args %v", op, f.Inst.Args, f.Inst.Args)
	log.Fatal("hi")
	switch op {
	case table.LIUnload:
	case table.LIImageDataType:
	case table.LIImageCodeType:
	case table.LIImageSize:
	case table.LIImageBase:
	case table.LILoadOptions:
	case table.LILoadOptionsSize:
	case table.LIReserved:
	case table.LIFilePath:
	case table.LIDeviceHandle:
	case table.LISystemTable:
	case table.LIParentHandle:
	case table.LIRevision:
	default:
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// OpenProtocol implements service.OpenProtocol
func (l *LoadedImage) OpenProtocol(f *Fault, h *Handle, g guid.GUID, ptr uintptr, ah, ch *Handle, attr uintptr) (*dispatch, error) {
	log.Panicf("here we are")
	return nil, fmt.Errorf("not yet")
}
