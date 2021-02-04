package protocol

import "testing"

func TestMarshal(t *testing.T) {
	if _, err := (&LoadedImage{}).Marshal(); err != nil {
		t.Errorf("LoadedImage: got %v, want nil", err)
	}
}
