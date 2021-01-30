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
	info.Signo = binary.LittleEndian.Uint32(si[0:4])
	info.Errno = int32(binary.LittleEndian.Uint32(si[4:8]))
	info.Code = int32(binary.LittleEndian.Uint32(si[8:12]))
	info.Addr = binary.LittleEndian.Uint64(si[16:24])
	return info, nil
}
