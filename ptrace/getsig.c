#define _POSIX_C_SOURCE 201212L
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stddef.h>


int
main() {
	siginfo_t si;
	printf("type siginfo [%ld]byte\n", sizeof(si));
	printf("func GetSigInfo(pid int) (&{"
		"var info = &unix.SignalfdSiginfo{}"
		"r1, r2, err := syscall.Syscall6(unix.PTRACE, unix.PTRACE_GETSIGINFO, pid ,0, unsafe.Pointer(&si[0], 0)"
		"if err != nil {"
		"return fmt.Errorf(\"PTRACE_GETSIGINFO FAILED  (%%v, %%v, %%v)\", r1, r2, err"
		"}");
	printf("var n int\n");
	printf("info.Signo, n = binary.Uvarint(si[%ld:%ld)\n", offsetof(siginfo_t, si_addr), offsetof(siginfo_t, si_addr)+ sizeof(si.si_signo));
	printf("if n < %ld {\nreturn fmt.Errorf(\"info.Signo: only got %%ld bytes\", n)\n}\n", sizeof(si.si_signo));
	printf("info.Errno, n = binary.Uvarint(si[%ld:%ld)\n", offsetof(siginfo_t, si_errno), offsetof(siginfo_t, si_errno) + sizeof(si.si_errno));
	printf("if n < %ld {\nreturn fmt.Errorf(\"info.Errno: only got %%ld bytes\", n)\n}\n", sizeof(si.si_errno));

	printf("info.Code, n = binary.Uvarint(si[%ld:%ld)\n", offsetof(siginfo_t, si_code), offsetof(siginfo_t, si_code) + sizeof(si.si_code));
	printf("if n < %ld {\nreturn fmt.Errorf(\"info.Code: only got %%ld bytes\", n)\n}\n", sizeof(si.si_code));
	
	printf("info.Addr, n = binary.Uvarint(si[%ld:%ld)\n", offsetof(siginfo_t, si_addr), offsetof(siginfo_t, si_addr) + sizeof(si.si_addr));
	printf("if n < %ld {\nreturn fmt.Errorf(\"info.Addr: only got %%ld bytes\", n)\n}\n", sizeof(si.si_addr));
	printf("}\n");

}
#if 0
// Go doesn't provide a way to get signals, so we manually implement it.
// This is basically ptrace(PTRACE_GETSIGINFO, ...)
siginfo_t getsig(pid_t pid) {
  siginfo_t rv;
  memset(&rv, 0, sizeof(siginfo_t));
  if(ptrace(PTRACE_GETSIGINFO, pid, NULL, &rv) != 0) {
    const int err = errno;
    fprintf(stderr, "error grabbing signal: %d\n", err);
    errno = err;
    return rv; // no multiple return values, and ptrs suck in Cgo...
  }
  return rv;
}

// Despite documentation, si_trapno is not actually a valid field.
int sig_trapno(siginfo_t si) { (void)si; assert(0); return 0; }
void* sig_addr(siginfo_t si) { return si.si_addr; }
#endif
