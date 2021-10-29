// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && (amd64 || arm64)
// +build linux
// +build amd64 arm64

package main

import (
	"debug/elf"
	"flag"
	"fmt"
	"syscall"

	"github.com/linuxboot/voodoo/trace"
)

func loadELF(t trace.Trace, n string, r *syscall.PtraceRegs, log func(string, ...interface{})) error {
	f, err := elf.Open(flag.Args()[0])
	if err != nil {
		return err
	}
	defer f.Close()
	eip := uintptr(f.Entry)
	for _, s := range f.Progs {
		log("Prog %v", s)
		if s.Type != elf.PT_LOAD {
			log("Skipping, not PT_LOAD")
		}
		addr := uintptr(s.Paddr)
		mem := make([]byte, s.Memsz)
		// TODO: poison?
		if false {
			for i := range mem {
				mem[i] = 0xf4
			}
		}
		if _, err := s.ReadAt(mem, 0); err != nil {
			log("Reading from %v: %v", s, err)
		}
		log("Write section to %#x:%#x", addr, len(mem))
		if err := t.Write(addr, mem); err != nil {
			return fmt.Errorf("Can't write %d bytes @ %#x for this Prog to process:%v", len(mem), addr, err)
		}
	}
	esp := uintptr(0x200000)
	setStack(r, esp)
	setPC(r, eip)
	log("ELF is loaded: eip is %#x, sp is %#x", eip, esp)
	// If you get really desperate, enable this.
	if false {
		nopnophlt := []byte{0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0xe0, 0x06, 0x20, 0xd4}
		if err := t.Write(uintptr(eip), nopnophlt); err != nil {
			return fmt.Errorf("Writing br . instruction: got %v, want nil", err)
		}
	}

	return nil
}
