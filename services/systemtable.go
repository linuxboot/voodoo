package services

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/linuxboot/voodoo/table"
)

var ()

// Runtime implements Service
type SystemTable struct {
	u  ServBase
	up ServPtr
}

var _ Service = &SystemTable{}

func init() {
	RegisterCreator("systemtable", NewSystemtable)
}

// NewSystemtable returns a Systemtable Service
// This must be the FIRST New called for a service.
// The system table is a kind of "root" of UEFI services, with pointers
// to boot, runtime, and other core services.
func NewSystemtable(tab []byte, u ServPtr) (Service, error) {
	var st = &SystemTable{up: u, u: u.Base()}

	for _, t := range []struct {
		n  string
		st uint64
	}{
		{"F42F7782-012E-4C12-9956-49F94304F721", table.ConOut},
		{"textin", table.ConIn},
		{"runtime", table.RuntimeServices},
		{"boot", table.BootServices},
	} {
		r, err := Base(tab, t.n)
		if err != nil {
			log.Fatal(err)
		}
		table.SystemTableNames[t.st].Val = uint64(r)
		Debug("-----------> Install service %s ptr t.st %#x at %#x", t.n, t.st, uint32(r))
		// r is the pointer. Set the pointer in the table.
		// the pointer is ... well ...wtf. I don't know.
		Debug("system table u is %#x", u)
		Debug("Install %#x at off %#x", r, t.st+0x10000)
		binary.LittleEndian.PutUint64(tab[t.st+0x10000:], uint64(r))
	}

	// Now set up all the GUIDServices
	for _, t := range GUIDServices {
		if _, err := Base(tab, t); err != nil {
			log.Fatal(err)
		}
	}

	// Now try the one function we know about.
	return st, nil
}

// Base implements service.Base
func (s *SystemTable) Base() ServBase {
	return s.u
}

// Base implements service.Ptr
func (s *SystemTable) Ptr() ServPtr {
	return s.up
}

// Call implements service.Call
func (r *SystemTable) Call(f *Fault) error {
	op := f.Op
	Debug("SystemTable Call: %v(%#x), arg type %T, args %v", table.SystemTableNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	log.Panic("unsupported SystemTable Call")
	return fmt.Errorf("SystemTable: No such offset %#x", op)
}
