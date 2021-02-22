package services

import "testing"

func TestNew(t *testing.T) {
	r, err := NewRuntime(1 << 20)
	if err != nil {
		t.Fatalf("NewRunTime: got %v, want nil", err)
	}
	// 1 is never valid as these are 4 or 8 aligned requests.
	if err := r.Call(1); err == nil {
		t.Fatalf("Call with bad value: got nil, want err")
	}
}
