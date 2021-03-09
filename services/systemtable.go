package services

import (
	"fmt"
	"log"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

var ()

// Runtime implements Service
type SystemTable struct {
	u ServBase
}

func init() {
	RegisterCreator("systemtable", NewSystemtable)
}

// NewSystemtable returns a Systemtable Service
// This must be the FIRST New called for a service.
func NewSystemtable(u ServBase) (Service, error) {
	var st = &SystemTable{}

	for _, t := range []struct {
		n  string
		st uint64
	}{
		{"textout", table.ConOut},
		{"textin", table.ConIn},
		{"runtime", table.RuntimeServices},
		{"boot", table.BootServices},
	} {
		r, err := Base(t.n)
		if err != nil {
			log.Fatal(err)
		}
		table.SystemTableNames[t.st].Val = uint64(r)
		log.Printf("-----------> Install service %s at %#x", t.n, r)
	}

	// Now set up all the GUIDServices
	for _, t := range GUIDServices {
		if _, err := Base(t); err != nil {
			log.Fatal(err)
		}
	}

	return st, nil
}

// Base implements service.Base
func (s *SystemTable) Base() ServBase {
	return s.u
}

// Call implements service.Call
func (r *SystemTable) Call(f *Fault) error {
	op := f.Op
	log.Printf("SystemTable Call: %v(%#x), arg type %T, args %v", table.SystemTableNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	log.Panic("unsupported SystemTable Call")
	return fmt.Errorf("SystemTable: No such offset %#x", op)
}

// Load implements service.Load
func (r *SystemTable) Load(f *Fault) error {
	op := f.Op
	log.Printf("SystemTable Load: %v(%#x), arg type %T, args %v", table.SystemTableNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	val, ok := table.SystemTableNames[uint64(op)]
	if ok {
		return retval(f, uintptr(val.Val))
	}
	return nil
}

// Store implements service.Store
func (r *SystemTable) Store(f *Fault) error {
	op := f.Op
	log.Printf("SystemTable Store: %v(%#x), arg type %T, args %v", table.SystemTableNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported SystemTable Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
