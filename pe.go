// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,amd64

package main

import (
	"debug/pe"
	"flag"
	"fmt"
	"syscall"

	"github.com/linuxboot/voodoo/trace"
)

func loadPE(t trace.Trace, n string, r *syscall.PtraceRegs, log func(string, ...interface{})) error {
	f, err := pe.Open(flag.Args()[0])
	if err != nil {
		return err
	}
	defer f.Close()
	h, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return fmt.Errorf("File type is %T, but has to be %T", f.OptionalHeader, pe.OptionalHeader64{})
	}
	// We need to relocate to start at *offset.
	// UEFI runs in page zero. I can't believe it.
	base := uintptr(h.ImageBase)
	eip := base + uintptr(h.BaseOfCode)
	heap := base + uintptr(h.SizeOfImage)
	// heap is at end  of the image.
	// Stack goes at top of reserved stack area.
	sp := heap + uintptr(h.SizeOfHeapReserve+h.SizeOfStackReserve)
	totalsize := int(h.SizeOfImage) + int(h.SizeOfHeapReserve+h.SizeOfStackReserve)
	if err := t.Write(base, make([]byte, totalsize)); err != nil {
		return fmt.Errorf("Can't write %d bytes of zero @ %#x for this section to process:%v", totalsize, base, err)
	}

	for i, s := range f.Sections {
		log("Section %d", i)
		log(show("\t", &s.SectionHeader))
		addr := base + uintptr(s.VirtualAddress)
		dat, err := s.Data()
		if err != nil {
			return fmt.Errorf("Can't get data for this section: %v", err)
		}
		// Zero it out.
		log("Copy section to %#x:%#x", addr, s.VirtualSize)
		bb := make([]byte, s.VirtualSize)
		if true {
			for i := range bb {
				bb[i] = 0xf4
			}
		}
		if err := t.Write(addr, bb); err != nil {
			return fmt.Errorf("Can't write %d bytes of zero @ %#x for this section to process:%v", len(bb), addr, err)
		}
		if false {
			if err := t.Write(addr, dat); err != nil {
				return fmt.Errorf("Can't write %d bytes of data @ %#x for this section to process: %v", len(dat), addr, err)
			}
		}
	}
	r.Rsp = uint64(sp)
	r.Rip = uint64(eip)
	return nil
}
