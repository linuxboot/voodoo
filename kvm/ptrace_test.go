package kvm

import (
	"runtime"
	"testing"
)

func TestTrace(t *testing.T) {
	runtime.GOMAXPROCS(4)

	tracee, err := Exec("/bin/true", []string{})
	if err != nil {
		t.Fatalf("Exec: got %v, want nil", err)
	}
	var n uint64
	for e := range tracee.Events() {
		t.Logf("Event %d, %v", n, e)
		n++
		if n == 1000 {
			if err := tracee.Detach(); err != nil {
				t.Fatalf("detach: got %v, want nil\n", err)
			}
			break
		}
		if err := tracee.SingleStep(); err != nil {
			t.Fatalf("step: got %v, want nil\n", err)
		}
	}
	/*
		if err := tracee.Error(); err != nil {
			t.Fatalf("error: %s\n", err.Error())
		}
	*/
	t.Logf("%d instructions\n", n)
}
