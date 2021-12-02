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
	"sync/atomic"
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

// Region defines a memory region.
// This is likely overkill; we likely don't want
// anything more than a single 2G region starting at 0.
type Region struct {
	slot uint32
	gpa  uint64
	data []byte
}

// OneRegister is the struct for getting or setting one register.
type OneRegister struct {
	id   uint64
	addr uint64
}

// VCPUInit is referenced but not defined in many kernels, it is a grab-bag
// for KVM startup on ARM.
type VCPUInit struct {
	target   uint32
	features [7]uint32
}

// A Tracee is a process that is being traced.
type Tracee struct {
	dev     *os.File
	vm      uintptr
	slot    uint32
	regions []*Region
	cpu     cpu
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

// String is a string for a Tracee
func (t *Tracee) String() string {
	return fmt.Sprintf("%s(kvmfd %d, vmfd %d, vcpufd %d)", t.dev.Name(), t.dev.Fd(), t.vm, t.cpu.fd)
}

// Event returns event information.
func (t *Tracee) Event() unix.SignalfdSiginfo {
	return t.info
}

// Tab returns the []byte for protocols.
func (t *Tracee) Tab() []byte {
	return t.tab
}

func (t *Tracee) vmioctl(option uintptr, data interface{}) (r1, r2 uintptr, err error) {
	var errno syscall.Errno
	switch option {
	default:
		p := &bytes.Buffer{}
		if err := binary.Write(p, binary.LittleEndian, data); err != nil {
			return 0, 0, err
		}
		r1, r2, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.vm), uintptr(option), uintptr(unsafe.Pointer(&p.Bytes()[0])))
		if false {
			Debug("cpuioctl: %#x, %#x, %v = syscall.Syscall(%#x, %d, %#x, %#x[%#x])", r1, r2, errno, syscall.SYS_IOCTL, uintptr(t.vm), uintptr(option), uintptr(unsafe.Pointer(&p.Bytes()[0])), p.Bytes())
		}
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
		p := &bytes.Buffer{}
		if err := binary.Write(p, binary.LittleEndian, data); err != nil {
			return 0, 0, err
		}

		r1, r2, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.cpu.fd), uintptr(option), uintptr(unsafe.Pointer(&p.Bytes()[0])))
		if false {
			Debug("cpuioctl: %#x, %#x, %v = syscall.Syscall(%#x, %d, %#x, %#x[%#x])", r1, r2, errno, syscall.SYS_IOCTL, uintptr(t.cpu.fd), uintptr(option), uintptr(unsafe.Pointer(&p.Bytes()[0])), p.Bytes())
		}
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

// SingleStep enables single stepping the guest
func (t *Tracee) SingleStep(onoff bool) error {
	// The only use we make of the struct, for now, is the size :-)
	var debug [unsafe.Sizeof(DebugControl{})]byte
	if onoff {
		debug[0] = Enable | SingleStep
		debug[2] = 0x0002
	}
	// this is not very nice, but it is easy.
	// And TBH, the tricks the Linux kernel people
	// play are a lot nastier.
	return ioctl(t.cpu.fd, setGuestDebug, uintptr(unsafe.Pointer(&debug[0])))
}

// Run runs the guest.
// Todo: see if we are in single step mode, if not, set, etc.
func (t *Tracee) Run() error {
	if err := ioctl(uintptr(t.cpu.fd), run, 0); err != nil {
		return err
	}
	if err := t.readInfo(); err != nil {
		log.Panicf("run: info %v", err)
	}
	return nil
}

// PID returns the PID for a Tracee.
// we'll return the cpuid for now.
func (t *Tracee) PID() int { return int(t.cpu.id) }

func version(f *os.File) int {
	r1, _, _ := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), kvmversion, 0)
	// syscall returns a non-nil error, always, even for 0.
	// if it fails, we'll get -1 and that's all we need to know.
	return int(r1)
}

// extensions makes sure we have all the extensions we need.
func extensions(f *os.File) error {
	exts := []struct {
		name string
		val  uintptr
	}{
		{"userMemory", capUserMemory},
		{"SyncMMU", capSyncMMU},
	}
	for _, s := range exts {
		r1, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), checkExtension, s.val)
		var err error
		if e != 0 {
			err = e
			return fmt.Errorf("Can't check extensions: %v", err)
		}
		if r1 == 0 {
			return fmt.Errorf("Required extension %v not present", s)
		}
		Debug("Extension %v is supported", s.name)
	}
	return nil
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

	if err := extensions(k); err != nil {
		return nil, err
	}

	vm, err := startvm(k)
	if err != nil {
		return nil, fmt.Errorf("startvm: failed (%d, %v)", vm, err)
	}

	t := &Tracee{
		dev: k,
		vm:  vm,
	}
	if err := t.archInit(); err != nil {
		return nil, err
	}
	return t, nil
}

// NewProc creates a CPU, given an id.
// TODO :we're getting sloppy about the t.do stuff, fix.
func (t *Tracee) NewProc(id int) error {
	if false {
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
		if err := t.archNewProc(); err != nil {
			return err
		}
	}
	return nil

}

// This allows setting up mem for a guest.
// This is not exposed because it's not supported by ptrace(2)
// and the trace model is the common subset of ptrace and kvm.
func (t *Tracee) mem(b []byte, base uint64) error {
	p := &bytes.Buffer{}
	u := &UserRegion{Slot: t.slot, Flags: 0, GPA: base, Size: uint64(len(b)), UserAddr: uint64(uintptr(unsafe.Pointer(&b[0])))}
	if err := binary.Write(p, binary.LittleEndian, u); err != nil {
		return err
	}
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

// ReadWord reads the given word from the inferior's address space.
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
	for _, r := range t.regions {
		if address < uintptr(r.gpa) {
			continue
		}
		last := r.gpa + uint64(len(r.data))
		if address > uintptr(last) {
			continue
		}
		a := address - uintptr(r.gpa)
		copy(data, r.data[a:])
		return nil
	}
	return fmt.Errorf("Address %#x is out of range", address)
}

// WriteWord writes the given word into the inferior's address space.
func (t *Tracee) WriteWord(address uintptr, word uint64) error {
	for _, r := range t.regions {
		if address < uintptr(r.gpa) {
			continue
		}
		last := r.gpa + uint64(len(r.data))
		if address > uintptr(last) {
			continue
		}
		a := address - uintptr(r.gpa)
		ptr := (*uint64)(unsafe.Pointer(&r.data[a]))
		Debug("WriteWord(%#x, %#x)", ptr, word)
		atomic.StoreUint64(ptr, word)
	}
	return nil
}

// Write writes data. It is not synchronized. yet.
func (t *Tracee) Write(address uintptr, data []byte) error {
	for _, r := range t.regions {
		if address < uintptr(r.gpa) {
			continue
		}
		last := r.gpa + uint64(len(r.data))
		if address > uintptr(last) {
			continue
		}
		a := address - uintptr(r.gpa)
		copy(r.data[a:], data)
		return nil
	}
	return fmt.Errorf("Address %#x is out of range", address)
}

// GetSiginfo reads the signal information for the signal that stopped the inferior.  Only
// valid on Unix if the inferior is stopped due to a signal.
func (t *Tracee) GetSiginfo() (*unix.SignalfdSiginfo, error) {
	return &t.info, nil
}

// Close closes a Tracee.
func (t *Tracee) Close() error {
	var err error
	return err
}
