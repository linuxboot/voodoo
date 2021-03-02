package services

import (
	"log"

	"github.com/linuxboot/voodoo/uefi"
)

const LoadedImageProtocol = "5B1B31A1-9562-11D2-8E3F-00A0C969723B"

// LoadedImage implements Service
type LoadedImage struct {
	u ServBase
}

func init() {
	RegisterCreator(LoadedImageProtocol, NewLoadedImage)
	GUIDServices = append(GUIDServices, LoadedImageProtocol)
}

// NewLoadedImage returns a LoadedImage Service
func NewLoadedImage(u ServBase) (Service, error) {
	return &LoadedImage{u: u}, nil
}

// Base implements service.Base
func (l *LoadedImage) Base() ServBase {
	return l.u
}

// Call implements service.Call
func (l *LoadedImage) Call(f *Fault) error {
	op := f.Op
	log.Printf("LoadedImage services: %#x, arg type %T, args %v", op, f.Inst.Args, f.Inst.Args)
	log.Fatal("hi")
	switch op {
	default:
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Load implements service.Load
func (r *LoadedImage) Load(f *Fault) error {
	op := f.Op
	log.Printf("LoadedImage services: %#x, arg type %T, args %v", op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported LoadedImage load")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Store implements service.Store
func (r *LoadedImage) Store(f *Fault) error {
	op := f.Op
	log.Printf("LoadedImage services: %#x, arg type %T, args %v", op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported LoadedImage Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
