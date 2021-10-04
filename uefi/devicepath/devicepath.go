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

package uefi

// Device path type values
const (
	End = 0x7f
	InstanceEnd = 1
	SubTypeEnd = 0xff
)

// Path is the generic Device Path type
type Path struct {
	Type uint8
	SubType uint8
	Length uint16
} 

// MAC is a mac address
type MAC struct {
	Addr[32] uint8
} 

const (
PathType = 	0x01
PathSubTypeMemory=		0x03
PathSubTypeVendor =	0x04
)

// Memory is for memory
type Memory struct {
	 DP Path
	Type uint32
	Start uint64
	End uint64
} 

// Vendor is for vendor data.
type efi_device_path_vendor {
	 DP Path
	GUID  guid.GUID

	Data[] uint8
} 

const (
	ACPI = 2
	SubTypeACPI = 1
)

#define EFI_PNP_ID(ID)				(u32)(((ID) << 16) | 0x41D0)
#define EISA_PNP_ID(ID)				EFI_PNP_ID(ID)
#define EISA_PNP_NUM(ID)			((ID) >> 16)

type efi_device_path_acpi_path {
	 DP Path
	hid uint32
	uid uint32
} 

#define DEVICE_PATH_TYPE_MESSAGING_DEVICE	0x03
#  define DEVICE_PATH_SUB_TYPE_MSG_ATAPI	0x01
#  define DEVICE_PATH_SUB_TYPE_MSG_SCSI		0x02
#  define DEVICE_PATH_SUB_TYPE_MSG_USB		0x05
#  define DEVICE_PATH_SUB_TYPE_MSG_MAC_ADDR	0x0b
#  define DEVICE_PATH_SUB_TYPE_MSG_USB_CLASS	0x0f
#  define DEVICE_PATH_SUB_TYPE_MSG_SD		0x1a
#  define DEVICE_PATH_SUB_TYPE_MSG_MMC		0x1d

type efi_device_path_atapi {
	 DP Path
	primary_secondary uint8
	slave_master uint8
	logical_unit_number uint16
} 

type efi_device_path_scsi {
	 DP Path
	target_id uint16
	logical_unit_number uint16
} 

type efi_device_path_usb {
	 DP Path
	parent_port_number uint8
	usb_interface uint8
} 

type efi_device_path_mac_addr {
	 DP Path
	 efi_mac_addr mac
	if_type uint8
} 

type efi_device_path_usb_class {
	 DP Path
	vendor_id uint16
	product_id uint16
	device_class uint8
	device_subclass uint8
	device_protocol uint8
} 

type efi_device_path_sd_mmc_path {
	 DP Path
	slot_number uint8
} 

#define DEVICE_PATH_TYPE_MEDIA_DEVICE		0x04
#  define DEVICE_PATH_SUB_TYPE_HARD_DRIVE_PATH	0x01
#  define DEVICE_PATH_SUB_TYPE_CDROM_PATH	0x02
#  define DEVICE_PATH_SUB_TYPE_FILE_PATH	0x04

type efi_device_path_hard_drive_path {
	DP Path
	partition_number uint32
	partition_start uint64
	partition_end uint64
	partition_signature[16] uint8
	partmap_type uint8
	signature_type uint8
} 

type efi_device_path_cdrom_path {
	 DP Path
	boot_entry uint32
	partition_start uint64
	partition_end uint64
} 

type efi_device_path_file_path {
	 DP Path
	str[] uint16
} 

var 	DevicePathGUID                                       = guid.MustParse(DEVICE_PATH_GUID)
