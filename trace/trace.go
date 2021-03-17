package trace

import (
	"fmt"
	"syscall"

	"github.com/linuxboot/voodoo/trace/kvm"
	"golang.org/x/sys/unix"
)

type Event interface{}

// Trace is the interface to a traced process
type Trace interface {
	// Exec starts a process in a trace
	NewProc(id int) error
	Exec(name string, args ...string) error
	ReadWord(address uintptr) (uint64, error)
	Read(address uintptr, data []byte) error
	Write(address uintptr, data []byte) error
	GetRegs() (*syscall.PtraceRegs, error)
	SetRegs(pr *syscall.PtraceRegs) error
	SingleStep(onoff bool) error
	ReArm() error
	Run() error
	Events() <-chan unix.SignalfdSiginfo
}

var Debug = func(string, ...interface{}) {}

// New returns a new Trace. The kind is determined by the parameter.
func New(n string) (Trace, error) {
	switch n {
	case "kvm":
		return kvm.New()
	default:
		return nil, fmt.Errorf("no such tracer as %s", n)
	}
}
