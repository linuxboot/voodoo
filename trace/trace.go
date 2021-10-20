package trace

import (
	"fmt"
	"syscall"

	"github.com/linuxboot/voodoo/trace/kvm"
	"golang.org/x/sys/unix"
)

// Trace is the interface to a traced process
type Trace interface {
	Event() unix.SignalfdSiginfo
	NewProc(id int) error
	ReadWord(address uintptr) (uint64, error)
	Read(address uintptr, data []byte) error
	Write(address uintptr, data []byte) error
	// TODO: now that we are multiarchitecture, create a regs
	// that has Args(), Results(), etc. and doesn't return PtraceRegs.
	GetRegs() (*syscall.PtraceRegs, error)
	SetRegs(pr *syscall.PtraceRegs) error
	SingleStep(onoff bool) error
	Run() error
	Tab() []byte
	// These three things are just special, machine to machine.
	Stack() (uintptr, error)
	PC() (uintptr, error)
	Flags() (uintptr, error)
	SetStack(uintptr) error
	SetPC(uintptr) error
	SetFlags() (uintptr, error)
}

var Debug = func(string, ...interface{}) {}

func SetDebug(f func(string, ...interface{})) {
	Debug = f
	kvm.Debug = f
}

// New returns a new Trace. The kind is determined by the parameter.
func New(n string) (Trace, error) {
	switch n {
	case "kvm":
		return kvm.New()
	default:
		return nil, fmt.Errorf("no such tracer as %s", n)
	}
}
