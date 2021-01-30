package ptrace

import (
	"syscall"
	"testing"
)

// This test is pretty broken.
func testDiedThenStep(t *testing.T) {
	tracee, err := Exec("/bin/true", []string{"/bin/true"})
	if err != nil {
		t.Fatalf("Exec: got %v, want nil", err)
	}
	if err := tracee.Continue(); err != nil {
		t.Fatalf("Continue: got %v, want nil", err)
	}
	stat := <-tracee.Events()
	if stat.(syscall.WaitStatus).Exited() {
		/* This *should* produce an error. */
		err := tracee.SingleStep()
		if err == nil {
			t.Fatalf("Step post exit: want err, got nil")
		}
	}
}
