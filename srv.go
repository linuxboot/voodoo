package main

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/protocol"
	"github.com/linuxboot/voodoo/ptrace"
)

// Srv serves different UEFI protocols.
func Srv(p *ptrace.Tracee, g *guid.GUID, args ...uintptr) error {
	// all this guid endianness shit is such a pain in the ass.
	// just string it and go.
	s := fmt.Sprintf("%s", g)

	switch s {
	case protocol.LoadedImageProtocol:
		i, err := protocol.NewLoadedImage()
		if err != nil {
			return err
		}

		b, err := i.Marshal()
		if err != nil {
			return fmt.Errorf("Can't serialize %T: %v", i, err)
		}
		if err := p.Write(dat, b); err != nil {
			return fmt.Errorf("Can't write %d bytes to %#x: %v", len(b), dat, err)
		}
		dat += uintptr(len(b))
		return nil

	default:
		return fmt.Errorf("Unknown GUID: %s", s)
	}
}
