package kvm

import (
	"golang.org/x/sys/unix"
)

// GetSigInfo gets the signal info for a pid into a *unix.SignalfdSiginfo
func (t *Tracee) GetSigInfo() (*unix.SignalfdSiginfo, error) {
	var info = &unix.SignalfdSiginfo{}
	return info, nil
}

