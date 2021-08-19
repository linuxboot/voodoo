package services

import (
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
)

// This is for the special ImageHandle at services.ImageHandle
// ImageHandle implements Service
type ImageHandle struct {
	u  ServBase
	up ServPtr
}

var (
	_ Service = &ImageHandle{}
)

func init() {
}

// Aliases implements Aliases
func (s *ImageHandle) Aliases() []string {
	return nil
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
func (s *ImageHandle) OpenProtocol(f *Fault, h *Handle, g guid.GUID, ptr uintptr, ah, ch *Handle, attr uintptr) (*dispatch, error) {
	log.Panicf("here we are")
	return nil, fmt.Errorf("not yet")
}
