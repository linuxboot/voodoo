package services

import (
	"fmt"
	"log"
)

// Func is a function selector.
type Func uint16

// ServBase is the base address of a service in memory, e.g. a Protocol struct,
// with a nice prefix to make it a printable string, like unto string names
// and GUIDs. Think of how git names stashes, with names that are still strings but
// that are not real refs -- safe idea. This seems weird but it's very convenient.
type ServBase string

// String is a stringer for ServBase
func (s ServBase) String() string {
	return string(s)
}

const servBaseFmt = "SB%#x"

// Service is the interface to services.
// In deference to the fact that we may be tracing
// more than one process, we pass the Tracee in as
// a parameter.
type Service interface {
	Call(f *Fault, op Func) error
	Base() ServBase
}

// serviceCreator returns a service. The parameter, u,
// is passed to it as an identifier.
type serviceCreator func(u ServBase) (Service, error)

var creators = map[string]serviceCreator{}

//var services = map[string]Service
var GUIDServices = []string{}

type dispatch struct {
	s    Service
	base ServBase
}

// dispatch contains both the nice print name of a service ("runtime") as
// well as GUID represented as strings.
var dispatches = map[ServBase]*dispatch{}
var dispatchService = map[string]ServBase{}

// RegisterCreator registers a service creator.
// Assumption: only called from init()
func RegisterCreator(n string, s serviceCreator) {
	if _, ok := creators[n]; ok {
		log.Fatalf("Register: %s is already registered", n)
	}
	creators[n] = s
}

// Base sets up a base address for a service. The base is chosen
// externally. When a DXE segvs, Dispatch will look up the Base
// and then dispatch to the correct Call function.
// Note that because this uses a string, one might set up names based
// on both a service name and a guid. Why, I have no idea.
func Base(base uintptr, n string) error {
	s, ok := creators[n]
	if !ok {
		return fmt.Errorf("Service %q does not exist", n)
	}
	b := servBaseName(base)
	if d, ok := dispatches[b]; ok {
		log.Panicf("Base %v for %s is in use by %v", b, n, d)
	}
	srv, err := s(b)
	if err != nil {
		return err
	}
	dispatchService[n] = b
	dispatches[b] = &dispatch{s: srv, base: b}
	return nil
}

func servBaseName(a uintptr) ServBase {
	return ServBase(fmt.Sprintf(servBaseFmt, a&^0xffff))
}

func splitBaseOp(a uintptr) (ServBase, Func) {
	return servBaseName(a), Func(a & 0xffff)
}

// Dispatch is called with n address. The address is
// split into a base and 16-bit offset. The base is not
// right-shifted or changed in any other way.
func Dispatch(f *Fault) error {
	a := uintptr(f.Info.Addr)
	b, op := splitBaseOp(a)
	d, ok := dispatches[b]
	if !ok {
		return fmt.Errorf("%#x: No such service in %v", a, d)
	}
	return d.s.Call(f, op)
}
