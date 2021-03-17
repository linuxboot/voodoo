package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func showinfo(i *unix.SignalfdSiginfo) string {
	return fmt.Sprintf(`Errno %#x    
Code %#x
Pid %#x
Uid %#x
Fd %#x 
Tid %#x
Band %#x
Overrun %#x
Trapno %#x 
Status %#x 
Int %#x    
Ptr %#x    
Utime %#x  
Stime %#x  
Addr %#x   
Addr_lsb %#x
Syscall %#x 
Call_addr %#x
Arch %#x
Signo %d
`,
		i.Errno,
		i.Code,
		i.Pid,
		i.Uid,
		i.Fd,
		i.Tid,
		i.Band,
		i.Overrun,
		i.Trapno,
		i.Status,
		i.Int,
		i.Ptr,
		i.Utime,
		i.Stime,
		i.Addr,
		i.Addr_lsb,
		i.Syscall,
		i.Call_addr,
		i.Arch, 
		i.Signo)
}
