package main

import (
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
)

func TestBad(t *testing.T) {
	var g guid.GUID
	if err := Srv(&g, func(...uintptr) error {
		return nil
	}); err == nil {
		t.Logf("got nil, want err")
	}
}
