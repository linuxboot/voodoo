package services

import "fmt"

// RunTime implements Service
type RunTime struct {
	base uintptr
}

func init() {
	Register("runtime", NewRuntime)
}

// NewRuntime returns a RunTime Service
func NewRuntime(b uintptr) (Service, error) {
	return &RunTime{base: b}, nil
}

// Call implements service.Call
func (r *RunTime) Call(f Func) error {
	switch f {
	default:
		return fmt.Errorf("%#x is not supported", f)
	}
	return nil
}
