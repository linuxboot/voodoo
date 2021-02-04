package main

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/guid"
)

// Srv serves different UEFI protocols.
func Srv(p *ptrace.Tracee, g *guid.GUID, error, args ...uintptr) error {
	switch g {
	case protocol.LoadedImageProtocol:
		i, err := protocol.NewLoadedImage()
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("Unknown GUID: %s", g)
	}
}
