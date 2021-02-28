package services

import (
	"fmt"
	"log"

	"github.com/linuxboot/voodoo/table"
)

var ()

// RunTime implements Service
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
func (r *SystemTable) Call(f *Fault, op Func) error {
	log.Printf("SystemTable services: %v(%#x), arg type %T, args %v", table.SystemTableNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	val, ok := table.SystemTableNames[uint64(op)]
	if ok {
		return retval(f, uintptr(val.Val))
	}
	return fmt.Errorf("SystemTable: No such offset %#x", op)
}
