package services

import (
	"encoding/binary"
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

const LoadedImageProtocol = "5B1B31A1-9562-11D2-8E3F-00A0C969723B"

// LoadedImage implements Service
type LoadedImage struct {
	u  ServBase
	up ServPtr
}

func init() {
	RegisterGUIDCreator(LoadedImageProtocol, NewLoadedImage)
}

// NewLoadedImage returns a LoadedImage Service
func NewLoadedImage(tab []byte, u ServPtr) (Service, error) {
	Debug("New LoadedImage ...")
	base := int(u) & 0xffffff
	for p := range table.LoadedImageTableNames {
		x := base + int(p)
		r := uint64(p) + 0xff400000 + uint64(base)
		switch p {
		}
		binary.LittleEndian.PutUint64(tab[x:], uint64(r))
		Debug("LoadedImage: Install %#x at off %#x", r, x)
	}

	Debug("Install LoadedImage(%#x) at %#x", base)

	return &LoadedImage{u: u.Base(), up: u}, nil
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
	default:
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
