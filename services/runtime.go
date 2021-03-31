package services

import (
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
func NewRuntime(b []byte, u ServPtr) (Service, error) {
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
	log.Printf("runtimeservices Call: %s(%#x), arg type %T, args %v", t, op, f.Inst.Args, f.Inst.Args)
	switch op {
	case table.RTGetVariable:
		args := trace.Args(f.Proc, f.Regs, 5)
		log.Printf("table.RTGetVariable args %#x", args)
		ptr := args[0]
		n, err := trace.ReadStupidString(f.Proc, ptr)
		if err != nil {
			return fmt.Errorf("Can't read StupidString at #%x, err %v", ptr, err)
		}
		var g guid.GUID
		if err := f.Proc.Read(args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", args[1], err)
		}
		log.Printf("PCHandleProtocol: find %s %s", n, g)
		f.Regs.Rax = uefi.EFI_SUCCESS
		v, err := uefi.ReadVariable(n, g)
		if err != nil {
			f.Regs.Rax = uefi.EFI_NOT_FOUND
			if err := f.Proc.SetRegs(f.Regs); err != nil {
				return err
			}
		}
		log.Printf("%s:%s: v is %v", n, g, v)
	case table.RTSetVariable:
		f.Regs.Rax = uefi.EFI_SUCCESS
		// whatever.
	default:
		log.Panic("fix me")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Load implements service.Load
func (r *Runtime) Load(f *Fault) error {
	op := f.Op
	f.Regs.Rax = uefi.EFI_SUCCESS
	t, ok := table.RuntimeServicesNames[uint64(op)]
	if !ok {
		log.Panicf("runtimeservices Load: No such op %#x", op)
	}
	log.Printf("runtimeservices Load: %s(%#x), arg type %T, args %v", t, op, f.Inst.Args, f.Inst.Args)
	ret := uintptr(op) + uintptr(r.Ptr())
	if err := retval(f, ret); err != nil {
		log.Panic(err)
	}
	return nil
}

// Store implements service.Store
func (r *Runtime) Store(f *Fault) error {
	op := f.Op
	t, ok := table.RuntimeServicesNames[uint64(op)]
	if !ok {
		log.Panicf("runtimeservices Store: No such op %#x", op)
	}
	log.Printf("runtimeservices Load: %s(%#x), arg type %T, args %v", t, op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported Runtime Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
