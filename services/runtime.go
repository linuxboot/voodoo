package services

import (
	"fmt"

	"github.com/linuxboot/voodoo/ptrace"
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
func (r *RunTime) Call(t *ptrace.Tracee, f Func) error {
	switch f {
	default:
		return fmt.Errorf("%#x is not supported", f)
	}
	return nil
}
