package ptrace

import (
	"fmt"
)

func clear_signals(pid int) error {
	//  errno := C.clearsignal(C.long(pid))
	errnum := 1 //int(errno)
	if errnum != 0 {
		return fmt.Errorf("could not clear signals, err=%d\n", errnum)
	}
	return nil
}
