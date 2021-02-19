package main

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/ptrace"
)

// Srv serves different UEFI protocols.
func Srv(p *ptrace.Tracee, g *guid.GUID, args ...uintptr) error {
	// all this guid endianness shit is such a pain in the ass.
	// just string it and go.
	s := fmt.Sprintf("%s", g)

	switch s {
	default:
		return fmt.Errorf("Unknown GUID: %s", s)
	}
}
