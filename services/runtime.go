package services

import (
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/ptrace"
	"github.com/linuxboot/voodoo/table"
)

// RunTime implements Service
type RunTime struct {
}

func init() {
	Register("runtime", NewRuntime)
}

// NewRuntime returns a RunTime Service
func NewRuntime() (Service, error) {
	return &RunTime{}, nil
}

// Call implements service.Call
func (r *RunTime) Call(f *Fault, op Func) error {
	switch op {
	case table.RTGetVariable:
		args := args(p, r, 5)
		log.Printf("table.RTGetVariable args %#x", args)
		ptr := args[0]
		n, err := p.ReadStupidString(ptr)
		if err != nil {
			return fmt.Errorf("Can't read StupidString at #%x, err %v", ptr, err)
		}
		var g guid.GUID
		if err := p.Read(args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", args[1], err)
		}
		log.Printf("PCHandleProtocol: find %s %s", n, g)
		v, err := ReadVariable(n, g)
		if err != nil {
			r.Rax = EFI_NOT_FOUND
			if err := p.SetRegs(r); err != nil {
				return err
			}
		}
		log.Printf("%s:%s: v is %v", n, g, v)
		r.Rax = EFI_SUCCESS
		return nil
	default:
		return fmt.Errorf("%#x is not supported in runtime services", f)
	}
	return nil
}
