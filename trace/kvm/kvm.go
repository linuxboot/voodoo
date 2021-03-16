// Package kvm provides an interface to the kvm system call.
package kvm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sigexit  = syscall.Signal(32)
	sigpause = syscall.Signal(33)
	sigtask  = syscall.Signal(34)
)

var (
	// ErrTraceeExited is returned when a command is executed on a tracee
	// that has already exited.
	ErrTraceeExited = errors.New("tracee exited")
	// Debug can be set externally to trace activity.
	Debug      = func(string, ...interface{}) {}
	deviceName = flag.String("kvmdevice", "/dev/kvm", "kvm device to use")
)

// DebugControl controls guest debug.
type DebugControl struct {
	Control  uint32
	_        uint32
	debugreg [8]uint64
}

// An Event is sent on a Tracee's event channel whenever it changes state.
type Event interface{}

// A Region defines a memory region.
// This is likely overkill; we likely don't want
// anything more than a single 2G region starting at 0.
type Region struct {
	slot uint32
	gpa  uint64
	data []byte
}

// A Tracee is a process that is being traced.
type Tracee struct {
	dev     *os.File
	vm      uintptr
	events  chan Event
	err     chan error
	cmds    chan func()
	slot    uint32
	regions []*Region
	cpu     cpu
}

func (t *Tracee) String() string {
	return fmt.Sprintf("%s", t.dev.Name())
}

func (t *Tracee) vmioctl(option uintptr, data interface{}) (r1, r2 uintptr, err error) {
	var errno syscall.Errno
	switch option {
	default:
		r1, r2, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.vm), uintptr(option), uintptr(unsafe.Pointer(&data)))
	}
	if errno != 0 {
		err = errno
	}
	return
}

func (t *Tracee) cpuioctl(option uintptr, data interface{}) (r1, r2 uintptr, err error) {
	var errno syscall.Errno
	switch option {
	default:
		r1, r2, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), uintptr(option), uintptr(unsafe.Pointer(&data)))
	}
	if errno != 0 {
		err = errno
	}
	return
}

func ioctl(fd uintptr, op uintptr, arg uintptr) (err error) {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
	if errno != 0 {
		err = errno
	}
	return
}

// EnableSingleStep enables single stepping the guest
func (t *Tracee) SingleStep(onoff bool) error {
	err := make(chan error, 1)
	if t.do(func() {
		var debug [unsafe.Sizeof(DebugControl{})]byte
		if onoff {
			debug[0] = Enable | SingleStep
		}
		// this is not very nice, but it is easy.
		// And TBH, the tricks the Linux kernel people
		// play are a lot nastier.
		err <- ioctl(t.cpu.fd, setGuestDebug, uintptr(unsafe.Pointer(&debug[0])))
	}) {
		return <-err
	}
	return ErrTraceeExited
}

// SingleStep continues the tracee for one instruction.
// Todo: see if we are in single step mode, if not, set, etc.
func (t *Tracee) Run() error {
	errc := make(chan error, 1)
	if t.do(func() {
		Debug("Step")
		e := ioctl(uintptr(t.cpu.fd), run, 0)
		errc <- e
	}) {
		err := <-errc
		Debug("run returns with %v", err)
		err = binary.Read(bytes.NewBuffer(t.cpu.m), binary.LittleEndian, &t.cpu.VMRun)
		return err
	}
	return ErrTraceeExited
}

// PID returns the PID for a Tracee.
// we'll return the cpuid for now.
func (t *Tracee) PID() int { return int(t.cpu.id) }

// Events returns the events channel for the tracee.
func (t *Tracee) Events() <-chan Event {
	return t.events
}

func version(f *os.File) int {
	r1, _, _ := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), kvmversion, 0)
	// syscall returns a non-nil error, always, even for 0.
	// if it fails, we'll get -1 and that's all we need to know.
	return int(r1)
}

func startvm(f *os.File) (uintptr, error) {
	r1, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), vmcreate, 0)
	if errno == 0 {
		return r1, nil
	}
	return r1, errno
}

// New returns a new Tracee. It will fail if the kvm device can not be opened.
// All the work done here is complex, but it all has to work or ... no kvm.
// But as soon as possible we shift to using the goroutine. FWIW.
func New() (*Tracee, error) {
	k, err := os.OpenFile(*deviceName, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if v := version(k); v != APIVersion {
		return nil, fmt.Errorf("Version: got %d, must be %d", v, APIVersion)
	}

	vm, err := startvm(k)
	if err != nil {
		return nil, fmt.Errorf("startvm: failed (%d, %v)", vm, err)
	}

	t := &Tracee{
		dev:    k,
		vm:     vm,
		events: make(chan Event, 1),
		err:    make(chan error, 1),
		cmds:   make(chan func()),
	}
	errs := make(chan error)
	go func() {
		// mmap and go don't really get along, so we'll not bother
		// with the mmap'ed bits for now.
		// if (kvm__check_extensions(kvm)) {
		// 	pr_err("A required KVM extension is not supported by OS");
		// 	ret = -ENOSYS;
		// 	goto err_vm_fd;
		// }

		// kvm__arch_init(kvm, kvm->cfg.hugetlbfs_path, kvm->cfg.ram_size);

		// kvm__init_ram(kvm);
		err := t.archInit()
		errs <- err
		if err != nil {
			return
		}
		go t.wait()
		t.trace()
	}()
	return t, <-errs
}

// createCPU creates a CPU, given an id.
// TODO :we're getting sloppy about the t.do stuff, fix.
func (t *Tracee) createCPU(id int) error {
	r1, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.vm), uintptr(createCPU), 0)
	if errno != 0 {
		return errno
	}
	fd := r1
	r1, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.dev.Fd()), vcpuMmapSize, 0)
	if errno != 0 {
		return errno
	}
	if r1 <= 0 {
		return fmt.Errorf("mmap size is <= 0")
	}
	msize := uint64(r1)
	b, err := unix.Mmap(int(fd), 0, int(msize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("cpu shared mmap(%#x, %#x, %#x, %#x, %#x): %v", fd, 0, msize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, err)
	}
	t.cpu.id = id
	t.cpu.fd = fd
	t.cpu.m = b
	return nil
}

// This allows setting up mem for a guest.
// This is not exposed because it's not supported by ptrace(2)
// and the trace model is the common subset of ptrace and kvm.
func (t *Tracee) mem(b []byte, base uint64) error {
	p := &bytes.Buffer{}
	u := &UserRegion{slot: t.slot, flags: 0, gpa: base, size: uint64(len(b)), useraddr: uint64(uintptr(unsafe.Pointer(&b[0])))}
	binary.Write(p, binary.LittleEndian, u)
	if false {
		log.Printf("ioctl %s", hex.Dump(p.Bytes()))
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.vm), uintptr(setMem), uintptr(unsafe.Pointer(&p.Bytes()[0])))
	if errno == 0 {
		t.regions = append(t.regions, &Region{slot: t.slot, gpa: base, data: b})
		t.slot++
		return nil
	}
	return errno
}

// Exec executes a process with tracing enabled, returning the Tracee
// or an error if an error occurs while executing the process.
func (t *Tracee) Exec(name string, argv ...string) error {
	errs := make(chan error)

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
		errs <- e
		if e != nil {
			return
		}
		go t.wait()
		t.trace()
	}()
	return <-errs
}

// Attach attaches to the given process.
func Attach(pid int) (*Tracee, error) {
	return nil, fmt.Errorf("Not supported yet")
}

// Detach detaches the tracee, destroying it in the process.
func (t *Tracee) Detach() error {
	if err := t.dev.Close(); err != nil {
		return err
	}
	return nil
}

// Continue makes the tracee execute unmanaged by the tracer.  Most commands are not
// possible in this state, with the notable exception of sending a
// syscall.SIGSTOP signal.
func (t *Tracee) Continue() error {
	err := make(chan error, 1)
	sig := 0
	if t.do(func() { err <- syscall.PtraceCont(int(t.dev.Fd()), sig) }) {
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
		err := syscall.PtraceSyscall(int(t.dev.Fd()), 0)
		errchan <- err
	}
	return <-errchan
}

// SendSignal sends the given signal to the tracee.
func (t *Tracee) SendSignal(sig syscall.Signal) error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.Kill(int(t.dev.Fd()), sig) }) {
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
		v, e := peek(int(t.dev.Fd()), address)
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
	if t.do(func() { err <- poke(int(t.dev.Fd()), address, word) }) {
		return <-err
	}
	return ErrTraceeExited
}

func (t *Tracee) Write(address uintptr, data []byte) error {
	err := make(chan error, 1)
	Debug("Write %#x %#x", address, data)
	if t.do(func() {
		_, e := syscall.PtracePokeData(int(t.dev.Fd()), address, data)
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
		_, e := syscall.PtracePeekData(int(t.dev.Fd()), address, data)
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

// GetSiginfo reads the signal information for the signal that stopped the inferior.  Only
// valid on Unix if the inferior is stopped due to a signal.
func (t *Tracee) GetSiginfo() (*unix.SignalfdSiginfo, error) {
	errchan := make(chan error, 1)
	value := make(chan *unix.SignalfdSiginfo, 1)
	if t.do(func() {
		si, err := GetSigInfo(int(t.dev.Fd()))
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
		errchan <- ClearSignals(int(int(t.dev.Fd())))
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

	syscall.Kill(int(t.dev.Fd()), syscall.SIGKILL)
	return err
}

// for what.
func (t *Tracee) wait() {
	defer close(t.err)
	sigs := make(chan os.Signal)
	signal.Notify(sigs, sigexit, sigpause, sigtask)
	for {
		select {
		case s := <-sigs:
			Debug("Got signal %v", s)
			if s.String() == "interrupt" {
				t.err <- fmt.Errorf(s.String())
			}
			t.events <- fmt.Sprintf("Signal %v", s)
		default:
		}
	}
}

func (t *Tracee) trace() {
	for cmd := range t.cmds {
		cmd()
	}
}
