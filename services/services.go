package services

import (
	"fmt"
	"log"
	"sync"

	"github.com/linuxboot/fiano/pkg/guid"
)

const (
	allocAmt = ServPtr(1 << 16)
	// ProtocolBase is the start of the KVM exit functions.
	ProtocolBase = ServPtr(0xff000000)
	servBaseFmt  = "SB%#x"
)

// Func is a function selector.
type Func uint16

type ServBase string
type ServPtr uint32

var (
	// memBase is the default allocation base for UEFI structs.
	memBase = ProtocolBase
	// AllocBase is the allocation base for DXE structs.
	allocBase uint32
	// resource allocation mutex.
	malloc sync.Mutex
	// Debug is for debugging messages.
	Debug = func(string, ...interface{}) {}
)

func bumpAllocate(amt uintptr, who string) ServPtr {
	malloc.Lock()
	defer malloc.Unlock()
	m := memBase
	memBase += ServPtr(amt)
	Debug("bumpAllocate for %s: %#x@%#x", who, amt, m)
	return m
}

func SetAllocBase(b uint32) {
	allocBase = b
}

// UEFIAllocate allocates memory for the DXE. If page is set,
// the alignment is 4k, else it is 8 bytes.
func UEFIAllocate(amt uintptr, page bool) uint32 {
	align := 3
	if page {
		amt *= 4096
		align = 12
	}
	malloc.Lock()
	defer malloc.Unlock()
	m := ((allocBase >> align) + 1) << align
	allocBase = m + uint32(amt)
	return m
}

// String is a stringer for ServBase
func (p *ServPtr) String() string {
	return fmt.Sprintf(servBaseFmt, uint32(*p))
}

// String is a stringer for ServBase
func (p *ServPtr) Base() ServBase {
	return ServBase(p.String())
}

// Service is the interface to services.
// In deference to the fact that we may be tracing
// more than one process, we pass the Tracee in as
// a parameter.
type Service interface {
	Call(f *Fault) error
	Base() ServBase
	Ptr() ServPtr
	OpenProtocol(f *Fault, h *Handle, g guid.GUID, ptr uintptr, ah, ch *Handle, attr uintptr) (*dispatch, error)
	Aliases() []string
}

// serviceCreator returns a service. The parameter, u,
// is passed to it as an identifier. The serviceCreator
// may itself call other serviceCreators.
type serviceCreator func(b []byte, u ServPtr) (Service, error)

var creators = map[string]serviceCreator{}

//var services = map[string]Service
var GUIDServices = []string{}

type dispatch struct {
	s  Service
	up ServPtr
}

func (d *dispatch) String() string {
	return fmt.Sprintf("%v %#x", d.s, d.up)
}

// dispatch contains both the nice print name of a service ("runtime") as
// well as GUID represented as strings.
var dispatches = map[ServBase]*dispatch{}

// RegisterCreator registers a service creator.
// Assumption: only called from init()
func RegisterCreator(n string, s serviceCreator) {
	if _, ok := creators[n]; ok {
		log.Fatalf("Register: %s is already registered", n)
	}
	creators[n] = s
}

// RegisterGUIDService registers a service named by a GUID.
// Assumption: only called from init()
func RegisterGUIDCreator(n string, s serviceCreator) {
	RegisterCreator(n, s)
	GUIDServices = append(GUIDServices, n)
}

// Base sets up a base address for a service. The base is chosen
// externally. When a DXE segvs, Dispatch will look up the Base
// and then dispatch to the correct Call function.
// Note that because this uses a string, one might set up names based
// on both a service name and a guid. Why, I have no idea.
func Base(tab []byte, n string) (ServPtr, error) {
	s, ok := creators[n]
	Debug("services.Base for %s: %v, %v", n, s, ok)
	if !ok {
		return 0, fmt.Errorf("Service %q does not exist", n)
	}
	if d, ok := dispatches[ServBase(n)]; ok {
		log.Panicf(" %s is in use by %v", n, d)
	}
	base := bumpAllocate(uintptr(allocAmt), n)
	b := base.Base()
	Debug("services.Base: base for %v is %#x %s", n, uint32(base), b)
	if d, ok := dispatches[b]; ok {
		log.Panicf("Base %v for %s is in use by %v", b, n, d)
	}
	srv, err := s(tab, base)
	if err != nil {
		return 0, err
	}
	d := &dispatch{s: srv, up: ServPtr(base)}
	Debug("Set up Dispatch for [%v,%v]: %s", b, n, d)
	dispatches[b] = d
	dispatches[ServBase(n)] = d
	for _, a := range srv.Aliases() {
		dispatches[ServBase(a)] = d
	}
	return base, nil
}

// BasePtr returns the base pointer for a service.
func BasePtr(n string) (ServPtr, bool) {
	d, ok := dispatches[ServBase(n)]
	if !ok {
		return 0, false
	}
	return d.up, true
}

func servBaseName(a uintptr) ServBase {
	// clear out the 0x400000 stuff. TODO: clean this shit up.
	a &= 0xffbfffff
	b := ServPtr(((a >> 16) << 16))
	return b.Base()
}

func splitBaseOp(a uintptr) (ServBase, Func) {
	return servBaseName(a), Func(a & 0xfff8)
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
	Debug("Dispatch %s", f.Asm)
	a := uintptr(f.Info.Addr)
	b, op := splitBaseOp(a)
	d, ok := dispatches[b]
	if !ok {
		Debug("Dispatch %s: Can't find %v", f.Asm, b)
		return fmt.Errorf("%#x: No such service in %v", a, d)
	}
	f.Op = op
	Debug("base %v op %#x d %v", b, op, d)
	return d.s.Call(f)
}
