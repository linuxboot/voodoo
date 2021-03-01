package services

import "testing"

func TestSplit(t *testing.T) {
	var tests = []struct {
		a uintptr
		b ServBase
		o Func
	}{
		{0xfedca, ServBase(0xf0000), 0xedca},
	}
	for _, tt := range tests {
		b, o := splitBaseOp(tt.a)
		if b != tt.b || o != tt.o {
			t.Errorf("split of %#x: got (%#x,%#x), want (#%x,%#x)", tt.a, b, o, tt.b, tt.o)
		}
	}
}
