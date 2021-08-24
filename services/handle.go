package services

import (
	"fmt"

	"github.com/linuxboot/fiano/pkg/guid"
)

// I had hoped to avoid this handle mess, but it seems unavoidable.
// Handles contain one or more Services.
// There is a "Handle Data Base" (yea right) which contains all handles.
// Handles are opaque, from what I can tell, so we return them as addresses
// that will cause ExitMmio. Services are referenced by GUID.

// handle is a handle descriptor
// It is returned from an open handle. It is an opaque value.
type hd uint64

type Handle struct {
	// convenience: remember our name.
	hd        hd
	protocols map[string]*dispatch
}

// Get gets a dispatch given a GUID.
func (h *Handle) Get(g *guid.GUID) (*dispatch, error) {
	d, ok := h.protocols[g.String()]
	if !ok {
		return nil, fmt.Errorf("No protocol for %v", g)
	}
	return d, nil
}

// Put puts a dispatch given a GUID. From what we know, it's ok to replace one.
func (h *Handle) Put(g *guid.GUID, aliases ...*guid.GUID) error {
	d, ok := dispatches[ServBase(g.String())]
	if !ok {
		return fmt.Errorf("No service for %v", g)
	}
	h.protocols[g.String()] = d

	for _, g := range aliases {
		h.protocols[g.String()] = d
	}
	return nil
}

// PutService puts a Service given given a GUID, Service, and base.
func (h *Handle) PutService(g *guid.GUID, s Service, u ServPtr) error {
	h.protocols[g.String()] = &dispatch{s: s, up: u}
	return nil
}

var (
	hdbase = 0x5eedface00000000
)

// return a new hd. TODO: let programs tweak it or something?
func newHD() hd {
	hdbase++
	return hd(hdbase)
}

// hdb is the "Handle Data Base"
// handle data base is such a bogus term I can't resist using it.
var hdb = map[hd]*Handle{}

func newHandle() *Handle {
	nh := &Handle{hd: newHD(), protocols: make(map[string]*dispatch)}
	hdb[nh.hd] = nh
	return nh
}

func getHandle(hd hd) (*Handle, error) {
	h, ok := hdb[hd]
	if !ok {
		return nil, fmt.Errorf("No handle for %v", hd)
	}
	return h, nil
}

func allHandlesByGUID(g *guid.GUID) []hd {
	var all []hd
	for _, h := range hdb {
		if _, err := h.Get(g); err != nil {
			all = append(all, h.hd)
		}
	}
	return all
}
