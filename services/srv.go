package services

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/protocol"
)

// Srv serves different UEFI protocols.
func Srv(f *Fault, g *guid.GUID, args ...uintptr) error {
	// all this guid endianness shit is such a pain in the ass.
	// just string it and go.
	s := fmt.Sprintf("%s", g)

	// See if it is copyable.
	c, ok := protocol.CopyAble[s]
	if !ok {
		return fmt.Errorf("Srv %s:We only handle copyable protocol handles at present", s)
	}
	dst := Allocate(len(c.Data))

	if err := f.Proc.Write(dst, c.Data); err != nil {
		return fmt.Errorf("Can't write %d bytes to %#x: %v", len(c.Data), dst, err)
	}
	fmt.Printf("returning to %#x %#x", f.Args, dst)
	err := retval(f, dst)
	return err
}
