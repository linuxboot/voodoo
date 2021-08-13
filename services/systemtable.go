package services

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

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
	x := index(u)
	Debug("NewSystemTable: %#x", u)
	// We need to install pointers into the system table.
	// This loop installs, first, each service, via the Base function.
	// Base allocates address space ranges, 64K-aligned and 64K-sized.
	// The first 4k page is 64-bit words, and each word is one of two things:
	// o "poison" value with low 2 bytes being a hlt;ret
	//   This allows the VMM to handle services by managing VM halt exits
	// o Pointer to a struct in memory
	//   VMM does not handle MMIO exits. So these pointers must be valid.
	// In some cases we need to add handles, as the UEFI forum missed lots
	// of memos on how to do OS design and have this weird polymorphic
	// handle thing.
	for _, t := range []struct {
		n                 string
		systemTableOffset uint64
	}{
		{uefi.ConOutGUID.String(), table.ConOut},
		{uefi.ConInGUID.String(), table.ConIn},
		{"runtime", table.RuntimeServices},
		{"boot", table.BootServices},
	} {
		r, err := Base(tab, t.n)
		if err != nil {
			log.Fatal(err)
		}
		table.SystemTableNames[t.systemTableOffset].Val = uint64(r)
		Debug("-----------> Install service %s ptr t.systemTableOffset %#x at %#x", t.n, t.systemTableOffset, uint32(r))
		// r is the pointer. Set the pointer in the table.
		// the pointer is ... well ...wtf. I don't know.
		Debug("system table u is %#x", u)
		// Recall that systemTableOffset is the offset of this element
		// of the struct.
		Debug("Install %#x at off %#x", r, t.systemTableOffset+uint64(x))
		binary.LittleEndian.PutUint64(tab[t.systemTableOffset+uint64(x):], uint64(r))
	}

	// Now set up all the GUIDServices
	for _, t := range GUIDServices {
		if _, err := Base(tab, t); err != nil {
			log.Fatal(err)
		}
	}

	// TODO: do better.
	h := newHandle()
	if err := h.Put(uefi.ConInGUID); err != nil {
		log.Fatal(err)
	}
	binary.LittleEndian.PutUint64(tab[table.ConInHandle+uint64(x):], uint64(h.hd))

	h = newHandle()
	if err := h.Put(uefi.ConOutGUID); err != nil {
		log.Fatal(err)
	}
	binary.LittleEndian.PutUint64(tab[table.ConOutHandle+uint64(x):], uint64(h.hd))

	h = newHandle()
	if err := h.Put(uefi.ConOutGUID); err != nil {
		log.Fatal(err)
	}
	binary.LittleEndian.PutUint64(tab[table.StdErrHandle+uint64(x):], uint64(h.hd))

	// Now try the one function we know about.
	return st, nil
}

// Aliases implements Aliases
func (s *SystemTable) Aliases() []string {
	return nil
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

// OpenProtocol implements service.OpenProtocol
func (s *SystemTable) OpenProtocol(f *Fault, h *Handle, prot *dispatch, g guid.GUID, ptr uintptr, ah, ch *Handle, attr uintptr) error {
	log.Panicf("here we are")
	return fmt.Errorf("not yet")
}
