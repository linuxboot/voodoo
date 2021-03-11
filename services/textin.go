package services

import (
	"log"
	"os"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// TextIn implements Service
type TextIn struct {
	u   ServBase
	up  ServPtr
	t   ServBase
	tup ServPtr
}

var _ Service = &TextIn{}

func init() {
	RegisterCreator("textin", NewTextIn)
}

// NewTextIn returns a TextIn Service
func NewTextIn(u ServPtr) (Service, error) {
	// We need to get to the TextInMode.
	tm, err := Base("textoutmode")
	if err != nil {
		return nil, err
	}
	log.Printf("NewTextIn: TextMode base is %#x %#x", tm, ServBase(tm))
	return &TextIn{u: ServBase(u.String()), up: u, t: ServBase(tm), tup: ServPtr(tm)}, nil
}

// Base implements service.Base
func (t *TextIn) Base() ServBase {
	return t.u
}

// Base implements service.Base
func (t *TextIn) Ptr() ServPtr {
	return t.up
}

// Call implements service.Call
func (t *TextIn) Call(f *Fault) error {
	op := f.Op
	log.Printf("TextIn services: %v(%#x), arg type %T, args %v", table.SimpleTextInServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	f.Regs.Rax = uefi.EFI_SUCCESS
	switch op {
	case table.STInReset:
	case table.STInReadKeyStroke:
		var b [1]byte
		if _, err := os.Stdin.Read(b[:]); err != nil {
			log.Printf("StdinRead fails: %v", err)
		}
	case table.STInWaitForKey:
		var b [1]byte
		if _, err := os.Stdin.Read(b[:]); err != nil {
			log.Printf("StdinRead fails: %v", err)
		}
	default:
		log.Panicf("unsup textout Call: %#x", op)
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Load implements service.Load
func (r *TextIn) Load(f *Fault) error {
	f.Regs.Rax = uefi.EFI_SUCCESS
	op := f.Op
	t, ok := table.SimpleTextInServicesNames[uint64(op)]
	if !ok {
		log.Panicf("unsupported TextIn Load of %#x", op)
	}
	ret := uintptr(op) + uintptr(r.up)
	switch op {
	default:
	case table.STOutMode:
		ret = uintptr(r.tup)
	}
	log.Printf("TextIn Load services: %v(%#x), arg type %T, args %v return %#x", t, op, f.Inst.Args, f.Inst.Args, ret)
	if err := retval(f, ret); err != nil {
		log.Panic(err)
	}
	return nil
}

// Store implements service.Store
func (r *TextIn) Store(f *Fault) error {
	op := f.Op
	log.Printf("TextIn Store services: %v(%#x), arg type %T, args %v", table.SimpleTextInServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported TextIn Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
