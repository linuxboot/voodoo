package devicepath

import (
	"bytes"
	"fmt"
	"testing"
)

func TestType(t *testing.T) {
	for i, tt := range []struct {
		p   Path
		out []byte
	}{
		{p: &Root{}, out: append([]byte{0x01, 0x04, 0x30, 0x00}, RootGUID[:]...)},
		{p: &End{}, out: []byte{0x7f, 0xff, 0x04, 0x00}},
	} {
		b := tt.p.Blob()
		t.Logf("Test %v out %#02x", tt.p, b)
		if !bytes.Equal(b, tt.out) {
			t.Errorf("Test %d: got %#02x, want %#02x", i, b, tt.out)
		}
	}
}

func TestPaths(t *testing.T) {
	Debug = t.Logf
	for i, tt := range []struct {
		p   string
		err error
		out []byte
	}{
		{p: "", err: nil, out: []byte{0x01, 0x04, 0x30, 0x00, 0xb9, 0x73, 0x1d, 0xe6, 0x84, 0xa3, 0xcc, 0x4a, 0xae, 0xab, 0x82, 0xe8, 0x28, 0xf3, 0x62, 0x8b}},
		{p: "blarg", err: fmt.Errorf("Unknown path type \"blarg\""), out: []byte{}},
		{p: "scsi", err: nil, out: []byte{0x01, 0x04, 0x30, 0x00, 0xb9, 0x73, 0x1d, 0xe6, 0x84, 0xa3, 0xcc, 0x4a, 0xae, 0xab, 0x82, 0xe8, 0x28, 0xf3, 0x62, 0x8b, 0x03, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}},
	} {
		p, err := Marshal(tt.p)
		if (err == nil && tt.err != nil) || (err != nil && tt.err == nil) {
			t.Errorf("Test %d: %v: got %v, want %v", i, tt, err, tt.err)
			continue
		}
		// if we expected an error, no need to check result.
		if tt.err != nil {
			continue
		}
		blob := Blob(p...)
		if !bytes.Equal(blob, tt.out) {
			t.Errorf("Test %d: %v: paths %v: got %#02x, want %#02x", i, tt.p, p, blob, tt.out)
			continue
		}
	}
}
