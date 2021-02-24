package services

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/protocol"
)

// Srv serves different UEFI protocols.
func Srv(f *Fault, g *guid.GUID) error {
	// all this guid endianness shit is such a pain in the ass.
	// just string it and go.
	s := fmt.Sprintf("%s", g)

	// See if it is copyable.
	c, ok := protocol.CopyAble[s]
	if !ok {
		return fmt.Errorf("Srv %s:We only handle copyable protocol handles at present", s)
	}
	if err := f.Proc.Write(f.Args[2], c.Data); err != nil {
		return fmt.Errorf("Can't write %d bytes to %#x: %v", len(c.Data), f.Args[2], err)
	}
	return nil
}
