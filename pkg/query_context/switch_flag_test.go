package query_context

import "testing"

func TestSwitchOfFastFlag(t *testing.T) {
	for f, want := range map[uint8]int{0: 0, 31: 0, 32: 1, 39: 8, 47: 16, 48: 0, 63: 0, 64: 0} {
		if got := SwitchOfFastFlag(f); got != want {
			t.Errorf("SwitchOfFastFlag(%d) = %d, want %d", f, got, want)
		}
	}
}
