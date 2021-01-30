#define _POSIX_C_SOURCE 201212L
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main() {
  siginfo_t si;
  printf("package ptrace\n");
  printf("import \"golang.org/x/sys/unix\"\n");
  printf("var si[%ld]byte\n", sizeof(si));
  printf("func GetSigInfo(pid int) (*unix.SignalfdSiginfo, error) {\n"
         "var info = &unix.SignalfdSiginfo{}\n"
         "r1, r2, errno := syscall.Syscall6(unix.SYS_PTRACE, "
         "unix.PTRACE_GETSIGINFO, uintptr(pid),0, "
         "uintptr(unsafe.Pointer(&si[0])), 0, 0)\n"
         "if errno != 0 {\n"
         "return nil, fmt.Errorf(\"PTRACE_GETSIGINFO FAILED  (%%v, %%v, "
         "%%v)\", r1, r2, errno);\n"
         "}\n");

  printf("info.Signo = binary.LittleEndian.Uint32(si[%ld:%ld])\n",
         offsetof(siginfo_t, si_signo),
         offsetof(siginfo_t, si_signo) + sizeof(si.si_signo));

  printf("info.Errno = int32(binary.LittleEndian.Uint32(si[%ld:%ld]))\n",
         offsetof(siginfo_t, si_errno),
         offsetof(siginfo_t, si_errno) + sizeof(si.si_errno));

  printf("info.Code = int32(binary.LittleEndian.Uint32(si[%ld:%ld]))\n",
         offsetof(siginfo_t, si_code),
         offsetof(siginfo_t, si_code) + sizeof(si.si_code));

  printf("info.Addr = binary.LittleEndian.Uint64(si[%ld:%ld])\n",
         offsetof(siginfo_t, si_addr),
         offsetof(siginfo_t, si_addr) + sizeof(si.si_addr));
  printf("return info, nil\n}\n");
}
