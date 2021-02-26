package services

import (
	"fmt"
	"log"

	"github.com/linuxboot/voodoo/table"
)

// RunTime implements Service
type SystemTable struct {
	u ServBase
}

func init() {
	RegisterCreator("systemtable", NewSystemtable)
}

// NewSystemtable returns a Systemtable Service
func NewSystemtable(u ServBase) (Service, error) {
	return &SystemTable{}, nil
}

// Base implements service.Base
func (s *SystemTable) Base() ServBase {
	return s.u
}

// Call implements service.Call
func (r *SystemTable) Call(f *Fault, op Func) error {
	log.Printf("SystemTable Service %v %#x", f, op)
	val, ok := table.SystemTableNames[uint64(op)]
	if ok {
		return retval(f, uintptr(val.Val))
	}
	return fmt.Errorf("SystemTable: No such offset %#x", op)
}
