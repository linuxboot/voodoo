package services

import (
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
)

var ()

// This is for the special ImageHandle at services.ImageHandle
// ImageHandle implements Service
type ImageHandle struct {
	u  ServBase
	up ServPtr
}

var _ Service = &ImageHandle{}

// this whole thing seems to have been a mistake.
func init() {
	// No need to register the creator; imagehandle is special
	// and is created at build time.
	return
	base := ImageHandleBase
	b := base.Base()
	i := &ImageHandle{up: base, u: b}
	d := &dispatch{s: i, up: ServPtr(base)}
	log.Printf("ImageHandleroot: Set up Dispatch for [%v,%v]: %s", b, "imagehandleroot", d)
	dispatches[b] = d
	dispatches["imagehandleroot"] = d
}

// Base implements service.Base
func (s *ImageHandle) Base() ServBase {
	return s.u
}

// Base implements service.Ptr
func (s *ImageHandle) Ptr() ServPtr {
	return s.up
}

// Call implements service.Call
func (r *ImageHandle) Call(f *Fault) error {
	log.Panic("unsupported ImageHandle Call")
	return fmt.Errorf("ImageHandle: can't be called")
}

// OpenProtocol implements service.OpenProtocol
func (s *ImageHandle) OpenProtocol(f *Fault, h, prot *dispatch, g guid.GUID, ptr uintptr, ah, ch *dispatch, attr uintptr) error {
	log.Panicf("here we are")
	return fmt.Errorf("not yet")
}
