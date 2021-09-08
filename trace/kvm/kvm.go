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
	m       *Machine
	events  chan unix.SignalfdSiginfo
	err     chan error
	cmds    chan func()
	slot    uint32
	regions []*Region
	cpu     cpu
	step    bool
	// This may seem a poor match but it makes
	// the program itself easier as ptrace and kvm
	// return common faultinfo, and other packages
	// understand it.
	info unix.SignalfdSiginfo
	// UEFI protocol tables
	// These consist of the structs for a given service. Some of these have
	// pointers which represent function calls to UEFI; pointers to data;
	// and data. The function pointers point to a hlt;ret instruction pair
	// as shown below.
	tab []byte
}

func (t *Tracee) String() string {
	return fmt.Sprintf("machine %v)", t.m)
}

func (t *Tracee) Tab() []byte {
	return t.m.mem[0xff000000:]
}

// EnableSingleStep enables single stepping the guest
func (t *Tracee) SingleStep(onoff bool) error {
	t.step = onoff
	return nil
}

// SingleStep continues the tracee for one instruction.
// Todo: see if we are in single step mode, if not, set, etc.
func (t *Tracee) Run() error {
	if t.step {
		// not sure what to do with the bool yet.
		_, err := t.m.RunOnce()
		return err
	}

	return t.m.RunInfiniteLoop()
}

// PID returns the PID for a Tracee.
// we'll return the cpuid for now.
func (t *Tracee) PID() int { return int(t.cpu.id) }

// Events returns the events channel for the tracee.
func (t *Tracee) Events() <-chan unix.SignalfdSiginfo {
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
	m, err := NewMachine()
	if err != nil {
		return nil, err
	}

	t := &Tracee{
		m:      m,
		events: make(chan unix.SignalfdSiginfo, 1),
		err:    make(chan error, 1),
		cmds:   make(chan func()),
	}
	return t, nil
}

// Exec executes a process with tracing enabled, returning the Tracee
// or an error if an error occurs while executing the process.
func (t *Tracee) Exec(name string, argv ...string) error {
	panic("Exec")
}

// Attach attaches to the given process.
func Attach(pid int) (*Tracee, error) {
	return nil, fmt.Errorf("Not supported yet")
}

// Detach detaches the tracee, destroying it in the process.
func (t *Tracee) Detach() error {
	panic("Detach")
}

// ReadWord reads the given word from the inferior's address space.
// Only allowed to read from Region 0 for now.
func (t *Tracee) ReadWord(address uintptr) (uint64, error) {
	var word [8]byte
	if err := t.Read(address, word[:]); err != nil {
		return 0, err
	}
	w := binary.LittleEndian.Uint64(word[:])
	return w, nil
}

// Read grabs memory starting at the given address, for len(data) bytes.
func (t *Tracee) Read(address uintptr, data []byte) error {
	var b = bytes.NewReader(t.m.mem)
	_, err := b.ReadAt(data, int64(address))
	return err
}

// WriteWord writes the given word into the inferior's address space.
func (t *Tracee) WriteWord(address uintptr, word uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], word)
	return t.Write(address, b[:])
}

func (t *Tracee) Write(address uintptr, data []byte) error {
	// sure wish we had bytes.WriterAt but oh well
	if address > uintptr(len(t.m.mem)) {
		return os.ErrInvalid
	}
	copy(t.m.mem[address:], data)
	return nil
}

// GetSiginfo reads the signal information for the signal that stopped the inferior.  Only
// valid on Unix if the inferior is stopped due to a signal.
func (t *Tracee) GetSiginfo() (*unix.SignalfdSiginfo, error) {
	return &t.info, nil
}

// Close closes a Tracee.
func (t *Tracee) Close() error {
	panic("close")
	return nil
}
