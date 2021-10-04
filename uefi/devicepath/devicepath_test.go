package devicepath

import "testing"

func TestType(t *testing.T) {
	for _, tt := range []Path{
		&Root{},
		&End{},
	} {
		t.Logf("Test %v", tt)
	}
}
