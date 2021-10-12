package services

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/trace"
	"github.com/linuxboot/voodoo/uefi"
)

// TextOut implements Service
type TextOut struct {
	u   ServBase
	up  ServPtr
	t   ServBase
	tup ServPtr
}

var _ Service = &TextOut{}

func init() {
	RegisterCreator(uefi.ConOutGUID.String(), NewTextOut)
}

// NewTextOut returns a TextOut Service
func NewTextOut(tab []byte, u ServPtr) (Service, error) {
	Debug("textout services table u is %#x", u)
	base := int(u) & 0xffffff
	for p := range table.SimpleTextOutServicesNames {
		x := base + int(p)
		r := uint64(p) + 0xff400000 + uint64(base)
		Debug("Install %#x at off %#x", r, x)
		binary.LittleEndian.PutUint64(tab[x:], uint64(r))
	}

	// We need to get to the TextOutMode.
	tm, err := Base(tab, "textoutmode")
	if err != nil {
		return nil, err
	}
	Debug("NewTextOut: TextMode base is %#x %#x", tm, ServBase(tm))
	return &TextOut{u: u.Base(), up: u, t: tm.Base(), tup: tm}, nil
}

// Aliases implements Aliases
func (t *TextOut) Aliases() []string {
	return nil
}

// Base implements service.Base
func (t *TextOut) Base() ServBase {
	return t.u
}

// Ptr implements service.Ptr
func (t *TextOut) Ptr() ServPtr {
	return t.up
}

// Call implements service.Call
func (t *TextOut) Call(f *Fault) error {
	op := f.Op
	Debug("TextOut services: %v(%#x), arg type %T, args %v", table.SimpleTextOutServicesNames[uint64(op)], op, f.Inst.Args, f.Inst.Args)
	f.SetEFIRetval(uefi.EFI_SUCCESS)
	switch op {
	case table.STOutReset:
		return nil
	case table.STOutEnableCursor:
		return nil
	case table.STOutOutputString:
		args := trace.Args(f.Proc, f.Regs, 6)
		Debug("StOutOutputString args %#x", args)
		n, err := trace.ReadStupidString(f.Proc, uintptr(args[1]))
		if err != nil {
			return err
		}
		fmt.Printf("%s", n)
		if err := f.Proc.SetRegs(f.Regs); err != nil {
			return err
		}
		return nil
	case table.STOutSetAttribute:
		Debug("Fuck STOutSetAttribute")
	case table.STOutMode:
		if err := retval(f, uintptr(t.tup)); err != nil {
			log.Panic(err)
		}
	default:
		log.Panicf("unsup textout Call: %#x", op)
		f.SetEFIRetval(uefi.EFI_UNSUPPORTED)
	}
	return nil
}

// OpenProtocol implements service.OpenProtocol
func (t *TextOut) OpenProtocol(f *Fault, h *Handle, g guid.GUID, ptr uintptr, ah, ch *Handle, attr uintptr) (*dispatch, error) {
	log.Panicf("here we are")
	return nil, fmt.Errorf("not yet")
}
