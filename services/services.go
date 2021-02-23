package services

import (
	"fmt"
	"log"
)

// Func is a function selector.
type Func uint16

// ServBase is the base address of a service in memory, e.g. a Protocol struct.
type ServBase uintptr

// Service is the interface to services.
// In deference to the fact that we may be tracing
// more than one process, we pass the Tracee in as
// a parameter.
type Service interface {
	Call(f *Fault, op Func) error
}

type serviceCreator func() (Service, error)

var services = map[string]serviceCreator{}
var dispatch = map[ServBase]Service{}

// Register registers services.
func Register(n string, s serviceCreator) {
	if _, ok := services[n]; ok {
		log.Fatalf("Register: %s is already registered", n)
	}
	services[n] = s
}

// Base sets up a base address for a service. The base is chosen
// externally. When a DXE segvs, Dispatch will look up the Base
// and then dispatch to the correct Call function.
// Note that because this uses a string, one might set up names based
// on both a service name and a guid. Why, I have no idea.
func Base(base uintptr, n string) error {
	s, ok := services[n]
	if !ok {
		return fmt.Errorf("Service %q does not exist", n)
	}
	b := ServBase(base)
	if d, ok := dispatch[b]; ok {
		return fmt.Errorf("Base %#x is in use by %v", base, d)
	}
	srv, err := s()
	if err != nil {
		return err
	}
	dispatch[b] = srv
	return nil
}

func splitBaseOp(a uintptr) (ServBase, Func) {
	return ServBase(a &^ 0xffff), Func(a & 0xffff)
}

// Dispatch is called with n address. The address is
// split into a base and 16-bit offset. The base is not
// right-shifted or changed in any other way.
func Dispatch(f *Fault) error {
	a := uintptr(f.Info.Addr)
	b, op := splitBaseOp(a)
	d, ok := dispatch[b]
	if !ok {
		return fmt.Errorf("%#x: No such service in %v", a, dispatch)
	}
	return d.Call(f, op)
}
