/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Extensible Firmware Interface
 * Based on 'Extensible Firmware Interface Specification' version 0.9,
 * April 30, 1999
 *
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *	Stephane Eranian <eranian@hpl.hp.com>
 *
 * From include/linux/efi.h in kernel 4.1 with some additions/subtractions
 */

package devicepath

import (
	"unsafe"

	"github.com/linuxboot/fiano/pkg/guid"
)

// Device path type values
const (
	EndType     = 0x7f
	InstanceEnd = 1
	SubTypeEnd  = 0xff
)

// Header is the common Device Path header.
type Header struct {
	Type    uint8
	SubType uint8
	Length  uint16
}

type Path interface {
	Header() Header
	// Blob return []byte so that they can easily be concatenated.
	Blob() []byte
}

// MAC is a MAC address
type MACAddress struct {
	Addr [32]uint8
}

const (
	TypeDevice    = 0x01
	SubTypeMemory = 0x03
	SubTypeVendor = 0x04
)

func hdrBlob(h Header) []byte {
	return []byte{h.Type, h.SubType, uint8(h.Length), uint8(h.Length >> 8)}
}

// End is an end of device path.
type End struct{}

var _ Path = &End{}

func (e *End) Header() Header {
	return Header{Type: EndType, SubType: SubTypeEnd, Length: uint16(unsafe.Sizeof(Header{}))}
}

func (e *End) Blob() []byte {
	return hdrBlob(e.Header())
}

// Root is a pre-filled-in Root record.
// Do we need it? u-boot did but who knows.
type Root struct{}

var _ Path = &Root{}

func (r *Root) Header() Header {
	return Header{Type: TypeDevice, SubType: SubTypeVendor, Length: uint16(unsafe.Sizeof(Vendor{}))}
}

func (r *Root) Blob() []byte {
	return hdrBlob(r.Header())
}

// Memory is for memory
type Memory struct {
	h     Header
	Type  uint32
	Start uint64
	End   uint64
}

var _ Path = &Memory{}

func (m *Memory) Header() Header {
	return m.h
}

func (m *Memory) Blob() []byte {
	return []byte{}
}

// Vendor is for vendor data.
type Vendor struct {
	h    Header
	GUID guid.GUID

	Data []uint8
}

const (
	TypeACPI    = 2
	SubTypeACPI = 1
)

func EFIPNPID(ID int) uint32 {
	return uint32((ID << 16) | 0x41d0)
}

/* do we need this EISA shit?
#define EFI_PNP_ID(ID)				(u32)(((ID) << 16) | 0x41D0)
#define EISA_PNP_ID(ID)				EFI_PNP_ID(ID)
#define EISA_PNP_NUM(ID)			((ID) >> 16)
*/

// an ACPI path
type ACPI struct {
	h   Header
	HID uint32
	UID uint32
}

// This section is called "UEFI doesn't understand storage abstractions"
const (
	TypeMessaging   = 3
	SubTypeATAPI    = 1
	SubTypeSCSI     = 2
	SubTypeUSB      = 5
	SubTypeMAC      = 0xb
	SubTypeUSBClass = 0xf
	SubTypeMSGSD    = 0x1a
	SubTypeMSGMMC   = 0x1d
)

type ATAPI struct {
	h                Header
	PrimarySecondary uint8
	// Cringe.
	// SlaveMaster uint8
	TargetHost uint8
	LUN        uint16
}

type SCSI struct {
	h        Header
	TargetID uint16
	LUN      uint16
}

type USB struct {
	h            Header
	ParentPort   uint8
	USBInterface uint8
}

type MAC struct {
	h      Header
	MAC    MACAddress
	IFType uint8
}

type USBClass struct {
	h              Header
	VID            uint16
	DID            uint16
	Class          uint8
	SubClass       uint8
	DeviceProtocol uint8
}

type MMC struct {
	h          Header
	SlotNumber uint8
}

const (
	TypeMedia        = 4
	SubTypeHardDrive = 1
	SubTypeCDROM     = 2
	SubTypeFile      = 4
)

type HardDrive struct {
	h                  Header
	Partition          uint32
	PartitionStart     uint64
	PartitionEnd       uint64
	PartitionSignature [16]uint8
	PartmapType        uint8
	SignatureType      uint8
}

type CDROM struct {
	h              Header
	BootEntry      uint32
	PartitionStart uint64
	PartitionEnd   uint64
}

type FILE struct {
	h Header
	// oh god UEFI.
	// String. uint16.
	str []uint16
}

const DEVICE_PATH_GUID = "09576E91-6D3F-11D2-8E39-00A0C969723B"

var DevicePathGUID = guid.MustParse(DEVICE_PATH_GUID)

var _ Path = &Vendor{}

func (v *Vendor) Header() Header {
	return v.h
}

func (v *Vendor) Blob() []byte {
	return []byte{}
}

var _ Path = &ACPI{}

func (a *ACPI) Header() Header {
	return a.h
}

func (a *ACPI) Blob() []byte {
	return []byte{}
}

var _ Path = &ATAPI{}

func (a *ATAPI) Header() Header {
	return a.h
}

func (a *ATAPI) Blob() []byte {
	return []byte{}
}

var _ Path = &SCSI{}

func (s *SCSI) Header() Header {
	return s.h
}

func (s *SCSI) Blob() []byte {
	return []byte{}
}

var _ Path = &USB{}

func (u *USB) Header() Header {
	return u.h
}

func (u *USB) Blob() []byte {
	return []byte{}
}

var _ Path = &MAC{}

func (m *MAC) Header() Header {
	return m.h
}

func (m *MAC) Blob() []byte {
	return []byte{}
}

var _ Path = &USBClass{}

func (u *USBClass) Header() Header {
	return u.h
}

func (u *USBClass) Blob() []byte {
	return []byte{}
}

var _ Path = &MMC{}

func (m *MMC) Header() Header {
	return m.h
}

func (m *MMC) Blob() []byte {
	return []byte{}
}

var _ Path = &HardDrive{}

func (h *HardDrive) Header() Header {
	return h.h
}

func (h *HardDrive) Blob() []byte {
	return []byte{}
}

var _ Path = &CDROM{}

func (c *CDROM) Header() Header {
	return c.h
}

func (c *CDROM) Blob() []byte {
	return []byte{}
}

var _ Path = &FILE{}

func (f *FILE) Header() Header {
	return f.h
}

func (f *FILE) Blob() []byte {
	return []byte{}
}
