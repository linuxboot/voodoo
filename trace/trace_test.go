package trace

import (
	"testing"

	"github.com/linuxboot/voodoo/trace/kvm"
)

func TestNew(t *testing.T) {
	if _, err := New("p"); err == nil {
		t.Errorf("%v: want error, got nil", "p")
	}
	if _, err := kvm.New(); err != nil {
		t.Errorf("kvm: want nil, got %v", err)
	}
}
