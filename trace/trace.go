package trace

import (
	"fmt"

	"github.com/linuxboot/voodoo/trace/kvm"
)

// Trace is the interface to a traced process
type Trace interface {
	// Exec starts a process in a trace
	Exec(name string, args ...string) error
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
