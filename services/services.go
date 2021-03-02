package services

import (
	"fmt"
	"log"
	"strings"
	"sync"
)

const (
	allocAmt = uintptr(1 << 16)
	// ImageHandle is the ServBase of the UEFI Image Handle
	ImageHandle = uintptr(0x100000)
)

// Func is a function selector.
type Func uint16

type ServBase uintptr

var (
	// memBase is the default allocation base for UEFI structs.
	memBase = ImageHandle + allocAmt
	// resource allocation mutex.
	malloc sync.Mutex
)

func bumpAllocate() uintptr {
	malloc.Lock()
	defer malloc.Unlock()
	m := memBase
	memBase += allocAmt
	return m
}

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
	Call(f *Fault) error
	Load(f *Fault) error
	Store(f *Fault) error
	Base() ServBase
}

// serviceCreator returns a service. The parameter, u,
// is passed to it as an identifier. The serviceCreator
// may itself call other serviceCreators.
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
func Base(n string) (uintptr, error) {
	s, ok := creators[n]
	if !ok {
		return 0, fmt.Errorf("Service %q does not exist", n)
	}
	base := bumpAllocate()
	b := servBaseName(base)
	if d, ok := dispatches[b]; ok {
		log.Panicf("Base %v for %s is in use by %v", b, n, d)
	}
	srv, err := s(b)
	if err != nil {
		return 0, err
	}
	dispatchService[n] = b
	dispatches[b] = &dispatch{s: srv, base: b}
	return base, nil
}

func servBaseName(a uintptr) ServBase {
	return ServBase(a &^ 0xffff)
}

func splitBaseOp(a uintptr) (ServBase, Func) {
	return servBaseName(a), Func(a & 0xffff)
}

// Service returns a service given an addr.
func AddrToService(addr uintptr) (Service, error) {
	a := uintptr(addr)
	b, _ := splitBaseOp(a)
	d, ok := dispatches[b]
	if !ok {
		return nil, fmt.Errorf("%#x: No such service in %v", a, d)
	}
	return d.s, nil
}

// Dispatch is called with an address. The address is
// split into a base and 16-bit offset. The base is not
// right-shifted or changed in any other way.
func Dispatch(f *Fault) error {
	log.Printf("Dispatch %s", f.Asm)
	a := uintptr(f.Info.Addr)
	b, op := splitBaseOp(a)
	d, ok := dispatches[b]
	if !ok {
		return fmt.Errorf("%#x: No such service in %v", a, d)
	}
	f.Op = op
	// Go (Plan 9) is CALL
	// gnu is call
	if strings.Contains(f.Asm, "CALL") || strings.Contains(f.Asm, "call") {
		return d.s.Call(f)
	}
	log.Printf("Arg 0 is %v, %T", f.Inst.Args[0], f.Inst.Args[0])
	switch f.Inst.Args[0].(type) {
	case Register:
		return d.s.Load(f)
	}
	return d.s.Store(f)

}
