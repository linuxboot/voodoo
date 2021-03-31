package services

import (
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
func NewLoadedImage(b []byte, u ServPtr) (Service, error) {
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
	log.Printf("LoadedImage Call: %#x, arg type %T, args %v", op, f.Inst.Args, f.Inst.Args)
	log.Fatal("hi")
	switch op {
	default:
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Load implements service.Load
func (r *LoadedImage) Load(f *Fault) error {
	f.Regs.Rax = uefi.EFI_SUCCESS
	op := f.Op
	t, ok := table.LoadedImageTableNames[uint64(op)]
	if !ok {
		log.Panicf("unsupported LoadedImage Load of %#x", op)
	}
	log.Printf("LoadedImage Load: %s(%#x), arg type %T, args %v", t, op, f.Inst.Args, f.Inst.Args)
	ret := uintptr(op) + uintptr(r.up)
	if err := retval(f, ret); err != nil {
		log.Panic(err)
	}
	return nil
}

// Store implements service.Store
func (r *LoadedImage) Store(f *Fault) error {
	op := f.Op
	log.Printf("LoadedImage Store: %#x, arg type %T, args %v", op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported LoadedImage Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
