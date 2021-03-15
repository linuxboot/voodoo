// Package kvm provides an interface to the kvm system call.
package kvm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	// ErrTraceeExited is returned when a command is executed on a tracee
	// that has already exited.
	ErrTraceeExited = errors.New("tracee exited")
	// Debug can be set externally to trace activity.
	Debug      = func(string, ...interface{}) {}
	deviceName = flag.String("kvmdevice", "/dev/kvm", "kvm device to use")
)

// An Event is sent on a Tracee's event channel whenever it changes state.
type Event interface{}

// A Tracee is a process that is being traced.
type Tracee struct {
	f      *os.File
	events chan Event
	err    chan error
	cmds   chan func()
}

func (t *Tracee) String() string {
	return fmt.Sprintf("%s", t.f.Name())
}

func (t *Tracee) ioctl(option int, data interface{}) error {
	var err error
	switch option {
	default:
		_, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.f.Fd()), uintptr(option), uintptr(unsafe.Pointer(&data)))
	}
	return err
}

func (t *Tracee) singleStep() error {
	return t.ioctl(setGuestDebug, &DebugControl{control: Enable | SingleStep})
}

// PID returns the PID for a Tracee.
func (t *Tracee) PID() int { return int(t.f.Fd()) }

// Events returns the events channel for the tracee.
func (t *Tracee) Events() <-chan Event {
	return t.events
}

func version(*os.File) (uint64, error) {
	//	ret = ioctl(kvm->sys_fd, KVM_GET_API_VERSION, 0);
	//	if (ret != KVM_API_VERSION) {
	//		pr_err("KVM_API_VERSION ioctl");
	//		ret = -errno;
	//		goto err_sys_fd;
	//	}
	return 12, nil

}

// New returns a new Tracee. It will fail if the kvm device can not be opened.
func New() (*Tracee, error) {
	k, err := os.OpenFile(*deviceName, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if v, err := version(k); err != nil || v != APIVersion {
		return nil, fmt.Errorf("Version: %d != %d or error %v", v, APIVersion, err)
	}
	t := &Tracee{
		f:      k,
		events: make(chan Event, 1),
		err:    make(chan error, 1),
		cmds:   make(chan func()),
	}
	return t, nil
}

// Exec executes a process with tracing enabled, returning the Tracee
// or an error if an error occurs while executing the process.
func (t *Tracee) Exec(name string, argv ...string) error {
	errs := make(chan error)
	proc := make(chan *os.File)

	go func() {
		// kvm->vm_fd = ioctl(kvm->sys_fd, KVM_CREATE_VM, KVM_VM_TYPE);
		// if (kvm->vm_fd < 0) {
		// 	pr_err("KVM_CREATE_VM ioctl");
		// 	ret = kvm->vm_fd;
		// 	goto err_sys_fd;
		// }

		// if (kvm__check_extensions(kvm)) {
		// 	pr_err("A required KVM extension is not supported by OS");
		// 	ret = -ENOSYS;
		// 	goto err_vm_fd;
		// }

		// kvm__arch_init(kvm, kvm->cfg.hugetlbfs_path, kvm->cfg.ram_size);

		// INIT_LIST_HEAD(&kvm->mem_banks);
		// kvm__init_ram(kvm);
		var e error
		proc <- t.f
		errs <- e
		if e != nil {
			return
		}
		go t.wait()
		t.trace()
	}()
	t.f = <-proc
	return <-errs
}

// Attach attaches to the given process.
func Attach(pid int) (*Tracee, error) {
	return nil, fmt.Errorf("Not supported yet")
}

// Detach detaches the tracee, destroying it in the process.
func (t *Tracee) Detach() error {
	if err := t.f.Close(); err != nil {
		return err
	}
	return nil
}

// SingleStep continues the tracee for one instruction.
func (t *Tracee) SingleStep() error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.PtraceSingleStep(int(t.f.Fd())) }) {
		return <-err
	}
	return ErrTraceeExited
}

// Continue makes the tracee execute unmanaged by the tracer.  Most commands are not
// possible in this state, with the notable exception of sending a
// syscall.SIGSTOP signal.
func (t *Tracee) Continue() error {
	err := make(chan error, 1)
	sig := 0
	if t.do(func() { err <- syscall.PtraceCont(int(t.f.Fd()), sig) }) {
		return <-err
	}
	return ErrTraceeExited
}

// Syscall runs the inferior until it hits, or returns from, a system call.
func (t *Tracee) Syscall() error {
	if t.cmds == nil {
		return ErrTraceeExited
	}
	errchan := make(chan error, 1)
	t.cmds <- func() {
		err := syscall.PtraceSyscall(int(t.f.Fd()), 0)
		errchan <- err
	}
	return <-errchan
}

// SendSignal sends the given signal to the tracee.
func (t *Tracee) SendSignal(sig syscall.Signal) error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.Kill(int(t.f.Fd()), sig) }) {
		return <-err
	}
	return ErrTraceeExited
}

// grabs a word at the given address.
func peek(pid int, address uintptr) (uint64, error) {
	word := make([]byte, 8 /* 8 should really be sizeof(uintptr)... */)
	nbytes, err := syscall.PtracePeekData(pid, address, word)
	if err != nil || nbytes != 8 /*sizeof(uintptr)*/ {
		return 0, err
	}
	v := uint64(0x2Bc0ffee)
	err = binary.Read(bytes.NewReader(word), binary.LittleEndian, &v)
	return v, err
}

// ReadWord reads the given word from the inferior's address space.
func (t *Tracee) ReadWord(address uintptr) (uint64, error) {
	err := make(chan error, 1)
	value := make(chan uint64, 1)
	if t.do(func() {
		v, e := peek(int(t.f.Fd()), address)
		value <- v
		err <- e
	}) {
		return <-value, <-err
	}
	return 0, errors.New("ReadWord: Unreachable")
}

// grabs a word at the given address.
func poke(pid int, address uintptr, word uint64) error {
	/* convert the word into the byte array that PtracePokeData needs. */
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, word)
	if err != nil {
		return err
	}

	nbytes, err := syscall.PtracePokeData(pid, address, buf.Bytes())
	if err != nil || nbytes != 8 /*sizeof(uint64)*/ {
		return err
	}
	return nil
}

// WriteWord writes the given word into the inferior's address space.
func (t *Tracee) WriteWord(address uintptr, word uint64) error {
	err := make(chan error, 1)
	if t.do(func() { err <- poke(int(t.f.Fd()), address, word) }) {
		return <-err
	}
	return ErrTraceeExited
}

func (t *Tracee) Write(address uintptr, data []byte) error {
	err := make(chan error, 1)
	Debug("Write %#x %#x", address, data)
	if t.do(func() {
		_, e := syscall.PtracePokeData(int(t.f.Fd()), address, data)
		err <- e
	}) {
		return <-err
	}
	return ErrTraceeExited
}

// Read grabs memory starting at the given address, for len(data) bytes.
func (t *Tracee) Read(address uintptr, data []byte) error {
	err := make(chan error, 1)
	if t.do(func() {
		_, e := syscall.PtracePeekData(int(t.f.Fd()), address, data)
		err <- e
	}) {
		return <-err
	}
	return ErrTraceeExited
}

// ReadStupidString reads a UEFI-style string, i.e. one composed of words, not bytes.
// We're gonna party like it's 1899.
func (t *Tracee) ReadStupidString(address uintptr) (string, error) {
	var s string
	var w [2]byte
	for {
		if err := t.Read(address, w[:]); err != nil {
			return "", err
		}
		if w[0] == 0 && w[1] == 0 {
			break
		}
		s = s + string(w[:1])
		address += 2
	}
	return s, nil
}

// GetRegs reads the registers from the inferior.
func (t *Tracee) GetRegs() (*syscall.PtraceRegs, error) {
	errchan := make(chan error, 1)
	value := make(chan *syscall.PtraceRegs, 1)
	if t.do(func() {
		var regs syscall.PtraceRegs
		err := syscall.PtraceGetRegs(int(t.f.Fd()), &regs)
		value <- &regs
		errchan <- err
	}) {
		return <-value, <-errchan
	}
	return &syscall.PtraceRegs{}, errors.New("GetRegs: Unreachable")
}

// GetIPtr reads the instruction pointer from the inferior and returns it.
func (t *Tracee) GetIPtr() (uintptr, error) {
	errchan := make(chan error, 1)
	value := make(chan uintptr, 1)
	if t.do(func() {
		var regs syscall.PtraceRegs
		regs.Rip = 0
		err := syscall.PtraceGetRegs(int(t.f.Fd()), &regs)
		value <- uintptr(regs.Rip)
		errchan <- err
	}) {
		return <-value, <-errchan
	}
	return 0, ErrTraceeExited
}

// SetIPtr sets the instruction pointer for a Tracee.
func (t *Tracee) SetIPtr(addr uintptr) error {
	errchan := make(chan error, 1)
	if t.do(func() {
		var regs syscall.PtraceRegs
		err := syscall.PtraceGetRegs(int(t.f.Fd()), &regs)
		if err != nil {
			errchan <- err
			return
		}
		regs.Rip = uint64(addr)
		err = syscall.PtraceSetRegs(int(t.f.Fd()), &regs)
		errchan <- err
	}) {
		return <-errchan
	}
	return ErrTraceeExited
}

// SetRegs sets regs for a Tracee.
func (t *Tracee) SetRegs(regs *syscall.PtraceRegs) error {
	errchan := make(chan error, 1)
	if t.do(func() {
		err := syscall.PtraceSetRegs(int(t.f.Fd()), regs)
		errchan <- err
	}) {
		return <-errchan
	}
	return ErrTraceeExited
}

// GetSiginfo reads the signal information for the signal that stopped the inferior.  Only
// valid on Unix if the inferior is stopped due to a signal.
func (t *Tracee) GetSiginfo() (*unix.SignalfdSiginfo, error) {
	errchan := make(chan error, 1)
	value := make(chan *unix.SignalfdSiginfo, 1)
	if t.do(func() {
		si, err := GetSigInfo(int(t.f.Fd()))
		errchan <- err
		value <- si
	}) {
		return <-value, <-errchan
	}
	return nil, ErrTraceeExited
}

// ClearSignal clears the last signal the inferior received.
// This could allow the inferior
// to continue after a segfault, for example.
func (t *Tracee) ClearSignal() error {
	errchan := make(chan error, 1)
	if t.do(func() {
		errchan <- ClearSignals(int(int(t.f.Fd())))
	}) {
		return <-errchan
	}
	return ErrTraceeExited
}

// Sends the command to the tracer go routine.	Returns whether the command
// was sent or not. The command may not have been sent if the tracee exited.
func (t *Tracee) do(f func()) bool {
	if t.cmds != nil {
		t.cmds <- f
		return true
	}
	return false
}

// Close closes a Tracee.
func (t *Tracee) Close() error {
	var err error
	select {
	case err = <-t.err:
	default:
		err = nil
	}
	close(t.cmds)
	t.cmds = nil

	syscall.Kill(int(t.f.Fd()), syscall.SIGKILL)
	return err
}

// for what.
func (t *Tracee) wait() {
	defer close(t.err)
	for {
		// state, err := t.proc.Wait()
		// if err != nil {
		// 	t.err <- err
		// 	close(t.events)
		// 	return
		// }
		// if state.Exited() {
		// 	t.events <- Event(state.Sys().(syscall.WaitStatus))
		// 	close(t.events)
		// 	return
		// }
		// t.events <- Event(state.Sys().(syscall.WaitStatus))
	}
}

func (t *Tracee) trace() {
	for cmd := range t.cmds {
		cmd()
	}
}
