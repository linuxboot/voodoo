package services

import (
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
)

// DevicePath implements Service
// But DevicePath *seems* to just be a blob of bytes.
// So it's a protocol, but it is just data?
// Who does this?
type DevicePath struct {
	u   ServBase
	up  ServPtr
	dat []byte
}

var _ Service = &DevicePath{}

// We don't register this here. It seems there can be
// lots of these attached to handles. This was a bit
// of the beauty of UEFI we did not understand at first.
// This whole Services architecture may be a total fuckup.
func init() {
}

// NewDevicePath returns a DevicePath Service.
// Still not todally sure what to do here, so it's empty.
// A DevicePath contains an pointer, not an embedded struct.
func NewDevicePath(tab []byte, u ServPtr) (Service, error) {
	return &DevicePath{}, nil
}

func (d *DevicePath) Aliases() []string {
	return nil
}

// Base implements service.Base
func (d *DevicePath) Base() ServBase {
	return d.u
}

// Ptr implements service.Ptr
func (d *DevicePath) Ptr() ServPtr {
	return d.up
}

// Call implements service.Call
func (d *DevicePath) Call(f *Fault) error {
	log.Panicf("DevicePath: can't call Call")
	return nil
}

// OpenProtocol implements service.OpenProtocol
func (d *DevicePath) OpenProtocol(f *Fault, h *Handle, g guid.GUID, ptr uintptr, ah, ch *Handle, attr uintptr) (*dispatch, error) {
	log.Panicf("here we are")
	return nil, fmt.Errorf("not yet")
}
