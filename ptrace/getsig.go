package ptrace

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var si [128]byte

func GetSigInfo(pid int) (*unix.SignalfdSiginfo, error) {
	var info = &unix.SignalfdSiginfo{}
	r1, r2, errno := syscall.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GETSIGINFO, uintptr(pid), 0, uintptr(unsafe.Pointer(&si[0])), 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("PTRACE_GETSIGINFO FAILED  (%v, %v, %v)", r1, r2, errno)
	}
	_64, n := binary.Uvarint(si[16:20])
	if n < 4 {
		return nil, fmt.Errorf("info.Signo: only got %d bytes", n)
	}
	info.Signo = uint32(_64)
	_64, n = binary.Uvarint(si[4:8])
	if n < 4 {
		return nil, fmt.Errorf("info.Errno: only got %d bytes", n)
		info.Errno = int32(_64)
	}
	_64, n = binary.Uvarint(si[8:12])
	if n < 4 {
		return nil, fmt.Errorf("info.Code: only got %d bytes", n)
	}
	info.Code = int32(_64)
	info.Addr, n = binary.Uvarint(si[16:24])
	if n < 8 {
		return nil, fmt.Errorf("info.Addr: only got %d bytes", n)
	}
	return info, nil
}
