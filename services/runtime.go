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

// Runtime implements Service
type Runtime struct {
	u  ServBase
	up ServPtr
}

func init() {
	RegisterCreator("runtime", NewRuntime)
}

// NewRuntime returns a Runtime Service
func NewRuntime(tab []byte, u ServPtr) (Service, error) {
	Debug("runtime services table u is %#x", u)
	base := int(u) & 0xffffff
	for p := range table.RuntimeServicesNames {
		x := base + int(p)
		r := uint64(p) + 0xff400000 + uint64(base)
		Debug("Install %#x at off %#x", r, x)
		binary.LittleEndian.PutUint64(tab[x:], uint64(r))
	}

	return &Runtime{u: u.Base(), up: u}, nil
}

// Base implements service.Base
func (r *Runtime) Base() ServBase {
	return r.u
}

// Base implements service.Ptr
func (r *Runtime) Ptr() ServPtr {
	return r.up
}

// Call implements service.Call
func (r *Runtime) Call(f *Fault) error {
	op := f.Op
	t, ok := table.RuntimeServicesNames[uint64(op)]
	if !ok {
		log.Panicf("runtimeservices Call No such op %#x", op)
	}
	Debug("runtimeservices Call: %s(%#x), arg type %T, args %v", t, op, f.Inst.Args, f.Inst.Args)
	switch op {
	case table.RTGetVariable:
		args := trace.Args(f.Proc, f.Regs, 5)
		Debug("table.RTGetVariable args %#x", args)
		ptr := args[0]
		n, err := trace.ReadStupidString(f.Proc, ptr)
		if err != nil {
			return fmt.Errorf("Can't read StupidString at #%x, err %v", ptr, err)
		}
		var g guid.GUID
		if err := f.Proc.Read(args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", args[1], err)
		}
		Debug("PCHandleProtocol: find %s %s", n, g)
		f.Regs.Rax = uefi.EFI_SUCCESS
		v, err := uefi.ReadVariable(n, g)
		if err != nil {
			f.Regs.Rax = uefi.EFI_NOT_FOUND
			if err := f.Proc.SetRegs(f.Regs); err != nil {
				return err
			}
		}
		Debug("%s:%s: v is %v", n, g, v)
	case table.RTSetVariable:
		f.Regs.Rax = uefi.EFI_SUCCESS
		// whatever.
	default:
		log.Panic("fix me")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// OpenProtocol implements service.OpenProtocol
func (r *Runtime) OpenProtocol(h, prot *dispatch, g guid.GUID, ptr uintptr, ah, ch *dispatch, attr uintptr) error {
	log.Panicf("here we are")
	return fmt.Errorf("not yet")
}
