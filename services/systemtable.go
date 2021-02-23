package services

import (
	"fmt"

	"github.com/linuxboot/voodoo/table"
)

// RunTime implements Service
type SystemTable struct {
}

func init() {
	Register("systemtable", NewSystemtable)
}

// NewSystemtable returns a Systemtable Service
func NewSystemtable() (Service, error) {
	return &SystemTable{}, nil
}

// Call implements service.Call
func (r *SystemTable) Call(f *Fault, op Func) error {
	val, ok := table.SystemTableNames[uint64(op)]
	if ok {
		return retval(f, uintptr(val.Val))
	}
	return fmt.Errorf("SystemTable: No such offset %#x", op)
}
