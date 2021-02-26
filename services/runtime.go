package services

import (
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/ptrace"
	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// RunTime implements Service
type RunTime struct {
	u ServBase
}

func init() {
	RegisterCreator("runtime", NewRuntime)
}

// NewRuntime returns a RunTime Service
func NewRuntime(u ServBase) (Service, error) {
	return &RunTime{u: u}, nil
}

// Base implements service.Base
func (r *RunTime) Base() ServBase {
	return r.u
}

// Call implements service.Call
func (r *RunTime) Call(f *Fault, op Func) error {
	log.Printf("runtimeservices: %s(%#x), arg type %T, args %v", table.BootServicesNames[int(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	case table.RTGetVariable:
		args := ptrace.Args(f.Proc, f.Regs, 5)
		log.Printf("table.RTGetVariable args %#x", args)
		ptr := args[0]
		n, err := f.Proc.ReadStupidString(ptr)
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
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
