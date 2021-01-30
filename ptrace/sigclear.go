package ptrace

// #cgo CFLAGS: -std=c99
// #include <stdlib.h>
// #include "clearsig.h"
import "C"

import(
  "fmt"
)

func clear_signals(pid int) error {
  errno := C.clearsignal(C.long(pid))
  errnum := int(errno)
  if errnum != 0 {
    return fmt.Errorf("could not clear signals, err=%d\n", errnum)
  }
  return nil
}
