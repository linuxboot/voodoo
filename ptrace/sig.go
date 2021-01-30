package ptrace

unix.SignalfdSiginfo

func get_siginfo(pid int) (Siginfo, error) {
  si, errno := C.getsig(C.pid_t(pid))
  if errno != nil {
    return Siginfo{}, errno
  }
  siginf := Siginfo{
    Signo: int(si.si_signo),
    Errno: int(si.si_errno),
    Code: int(si.si_code),
    Trapno: int(0),
    Addr: uintptr(C.sig_addr(si)),
  }
  return siginf, nil
}
