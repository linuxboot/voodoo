package main

import (
	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/knownguids"
)

// NameToGUID is a mapping of name to GUID. It is built
// at startup from knownguids.
var NameToGUID = map[string]guid.GUID{}

func init() {
	for g, n := range knownguids.GUIDs {
		NameToGUID[n] = g
	}
}
