package protocol

import (
	"testing"

	"github.com/u-root/u-root/pkg/uefivars"
)

func TestBad(t *testing.T) {
	var g uefivars.MixedGUID
	if err := Srv(&g); err == nil {
		t.Logf("got nil, want err")
	}
}
