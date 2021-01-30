package ptrace

import (
	"fmt"
)

// ClearSignals clears all pending signals for a Tracee.
func ClearSignals(pid int) error {
	//  errno := C.clearsignal(C.long(pid))
	errnum := 1 //int(errno)
	if errnum != 0 {
		return fmt.Errorf("Could not clear signals for pid %d: %v", pid, errnum)
	}
	return nil
}
