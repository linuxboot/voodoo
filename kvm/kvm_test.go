package kvm

import (
	"log"
	"testing"
)

func TestOpen(t *testing.T) {
	v, err := Exec("", []string{""})
	if err != nil {
		t.Fatalf("Open: got %v, want nil", err)
	}
	log.Printf("%v", v)
}
