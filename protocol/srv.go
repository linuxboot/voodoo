package protocol

import (
	"fmt"

	"github.com/u-root/u-root/pkg/uefivars"
)

// Srv serves different UEFI protocols.
func Srv(g *uefivars.MixedGUID, args ...uintptr) error {
	switch g {
	default:
		return fmt.Errorf("Unknown GUID: %s", g)
	}
}
