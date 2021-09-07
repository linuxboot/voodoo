package kvm

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/bobuhiro11/gokvm/kvm"
	"github.com/bobuhiro11/gokvm/serial"
)

// InitialRegState GuestPhysAddr                      Binary files [+ offsets in the file]
//
//                 0x00000000    +------------------+
//                               |                  |
// RSI -->         0x00010000    +------------------+ bzImage [+ 0]
//                               |                  |
//                               |  boot param      |
//                               |                  |
//                               +------------------+
//                               |                  |
//                 0x00020000    +------------------+
//                               |                  |
//                               |   cmdline        |
//                               |                  |
//                               +------------------+
//                               |                  |
// RIP -->         0x00100000    +------------------+ bzImage [+ 512 x (setup_sects in boot param header + 1)]
//                               |                  |
//                               |   64bit kernel   |
//                               |                  |
//                               +------------------+
//                               |                  |
//                 0x0f000000    +------------------+ initrd [+ 0]
//                               |                  |
//                               |   initrd         |
//                               |                  |
//                               +------------------+
//                               |                  |
//                 0x40000000    +------------------+
const (
	memSize = 4 << 30
)

type Machine struct {
	kvmFd, vmFd, vcpuFd uintptr
	mem                 []byte
	run                 *kvm.RunData
	serial              *serial.Serial
	ioportHandlers      [0x10000][2]func(m *Machine, port uint64, bytes []byte) error
}

func NewMachine() (*Machine, error) {
	m := &Machine{}

	devKVM, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0o644)
	if err != nil {
		return m, err
	}

	m.kvmFd = devKVM.Fd()
	m.vmFd, err = kvm.CreateVM(m.kvmFd)

	if err != nil {
		return m, err
	}

	if err := kvm.SetTSSAddr(m.vmFd); err != nil {
		return m, err
	}

	if err := kvm.SetIdentityMapAddr(m.vmFd); err != nil {
		return m, err
	}

	if err := kvm.CreateIRQChip(m.vmFd); err != nil {
		return m, err
	}

	if err := kvm.CreatePIT2(m.vmFd); err != nil {
		return m, err
	}

	m.vcpuFd, err = kvm.CreateVCPU(m.vmFd)
	if err != nil {
		return m, err
	}

	if err := m.initCPUID(); err != nil {
		return m, err
	}

	m.mem, err = syscall.Mmap(-1, 0, memSize,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_ANONYMOUS)
	if err != nil {
		return m, err
	}

	mmapSize, err := kvm.GetVCPUMMmapSize(m.kvmFd)
	if err != nil {
		return m, err
	}

	r, err := syscall.Mmap(int(m.vcpuFd), 0, int(mmapSize), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return m, err
	}

	m.run = (*kvm.RunData)(unsafe.Pointer(&r[0]))

	err = kvm.SetUserMemoryRegion(m.vmFd, &kvm.UserspaceMemoryRegion{
		Slot: 0, Flags: 0, GuestPhysAddr: 0, MemorySize: 1 << 30,
		UserspaceAddr: uint64(uintptr(unsafe.Pointer(&m.mem[0]))),
	})
	if err != nil {
		return m, err
	}

	return m, nil
}

// RunData returns the kvm.RunData for the VM
func (m *Machine) RunData() *kvm.RunData {
	return m.run

}
func (m *Machine) LoadLinux(bzImagePath, initPath, params string) error {
	log.Panicf("%s %s %s: no", bzImagePath, initPath, params)
	return nil
	// // Load initrd
	// initrd, err := ioutil.ReadFile(initPath)
	// if err != nil {
	// 	return err
	// }

	// for i := 0; i < len(initrd); i++ {
	// 	m.mem[initrdAddr+i] = initrd[i]
	// }

	// // Load kernel command-line parameters
	// for i, b := range []byte(params) {
	// 	m.mem[cmdlineAddr+i] = b
	// }

	// m.mem[cmdlineAddr+len(params)] = 0 // for null terminated string

	// // Load Boot Param
	// bootParam, err := bootparam.New(bzImagePath)
	// if err != nil {
	// 	return err
	// }

	// // refs https://github.com/kvmtool/kvmtool/blob/0e1882a49f81cb15d328ef83a78849c0ea26eecc/x86/bios.c#L66-L86
	// bootParam.AddE820Entry(
	// 	bootparam.RealModeIvtBegin,
	// 	bootparam.EBDAStart-bootparam.RealModeIvtBegin,
	// 	bootparam.E820Ram,
	// )
	// bootParam.AddE820Entry(
	// 	bootparam.EBDAStart,
	// 	bootparam.VGARAMBegin-bootparam.EBDAStart,
	// 	bootparam.E820Reserved,
	// )
	// bootParam.AddE820Entry(
	// 	bootparam.MBBIOSBegin,
	// 	bootparam.MBBIOSEnd-bootparam.MBBIOSBegin,
	// 	bootparam.E820Reserved,
	// )
	// bootParam.AddE820Entry(
	// 	kernelAddr,
	// 	memSize-kernelAddr,
	// 	bootparam.E820Ram,
	// )

	// bootParam.Hdr.VidMode = 0xFFFF                                                                  // Proto ALL
	// bootParam.Hdr.TypeOfLoader = 0xFF                                                               // Proto 2.00+
	// bootParam.Hdr.RamdiskImage = initrdAddr                                                         // Proto 2.00+
	// bootParam.Hdr.RamdiskSize = uint32(len(initrd))                                                 // Proto 2.00+
	// bootParam.Hdr.LoadFlags |= bootparam.CanUseHeap | bootparam.LoadedHigh | bootparam.KeepSegments // Proto 2.00+
	// bootParam.Hdr.HeapEndPtr = 0xFE00                                                               // Proco 2.01+
	// bootParam.Hdr.ExtLoaderVer = 0                                                                  // Proco 2.02+
	// bootParam.Hdr.CmdlinePtr = cmdlineAddr                                                          // Proco 2.06+
	// bootParam.Hdr.CmdlineSize = uint32(len(params) + 1)                                             // Proco 2.06+

	// bytes, err := bootParam.Bytes()
	// if err != nil {
	// 	return err
	// }

	// for i, b := range bytes {
	// 	m.mem[bootParamAddr+i] = b
	// }

	// // Load kernel
	// bzImage, err := ioutil.ReadFile(bzImagePath)
	// if err != nil {
	// 	return err
	// }

	// // copy to g.mem with offest setupsz
	// //
	// // The 32-bit (non-real-mode) kernel starts at offset (setup_sects+1)*512 in
	// // the kernel file (again, if setup_sects == 0 the real value is 4.) It should
	// // be loaded at address 0x10000 for Image/zImage kernels and 0x100000 for bzImage kernels.
	// //
	// // refs: https://www.kernel.org/doc/html/latest/x86/boot.html#loading-the-rest-of-the-kernel
	// offset := int(bootParam.Hdr.SetupSects+1) * 512

	// for i := 0; i < len(bzImage)-offset; i++ {
	// 	m.mem[kernelAddr+i] = bzImage[offset+i]
	// }

	// if err = m.initRegs(); err != nil {
	// 	return err
	// }

	// if err = m.initSregs(); err != nil {
	// 	return err
	// }

	// m.initIOPortHandlers()

	// serialIRQCallback := func(irq, level uint32) {
	// 	if err := kvm.IRQLine(m.vmFd, irq, level); err != nil {
	// 		panic(err)
	// 	}
	// }

	// if m.serial, err = serial.New(serialIRQCallback); err != nil {
	// 	return err
	// }

	// return nil
}

func (m *Machine) GetInputChan() chan<- byte {
	return m.serial.GetInputChan()
}

func (m *Machine) InjectSerialIRQ() {
	m.serial.InjectIRQ()
}

func (m *Machine) initRegs(rip, arg0 uint64) error {
	regs, err := kvm.GetRegs(m.vcpuFd)
	if err != nil {
		return err
	}

	regs.RFLAGS = 2
	regs.RIP = rip
	regs.RSI = arg0

	if err := kvm.SetRegs(m.vcpuFd, regs); err != nil {
		return err
	}

	return nil
}

func (m *Machine) GetRegs() (kvm.Regs, error) {
	return kvm.GetRegs(m.vcpuFd)
}

func (m *Machine) SetRegs(*kvm.Regs) error {
	return kvm.SetRegs(m.vcpuFd, regs)
}

func (m *Machine) initSregs() error {
	sregs, err := kvm.GetSregs(m.vcpuFd)
	if err != nil {
		return err
	}

	// set all segment flat
	sregs.CS.Base, sregs.CS.Limit, sregs.CS.G = 0, 0xFFFFFFFF, 1
	sregs.DS.Base, sregs.DS.Limit, sregs.DS.G = 0, 0xFFFFFFFF, 1
	sregs.FS.Base, sregs.FS.Limit, sregs.FS.G = 0, 0xFFFFFFFF, 1
	sregs.GS.Base, sregs.GS.Limit, sregs.GS.G = 0, 0xFFFFFFFF, 1
	sregs.ES.Base, sregs.ES.Limit, sregs.ES.G = 0, 0xFFFFFFFF, 1
	sregs.SS.Base, sregs.SS.Limit, sregs.SS.G = 0, 0xFFFFFFFF, 1

	sregs.CS.DB, sregs.SS.DB = 1, 1
	sregs.CR0 |= 1 // protected mode

	if err := kvm.SetSregs(m.vcpuFd, sregs); err != nil {
		return err
	}

	return nil
}

func (m *Machine) GetSregs() (kvm.Sregs, error) {
	return kvm.GetSregs(m.vcpuFd)
}

func (m *Machine) SetSregs(*kvm.Sregs) error {
	return kvm.SetSregs(m.vcpuFd, regs)
}

func (m *Machine) initCPUID() error {
	cpuid := kvm.CPUID{}
	cpuid.Nent = 100

	if err := kvm.GetSupportedCPUID(m.kvmFd, &cpuid); err != nil {
		return err
	}

	// https://www.kernel.org/doc/html/latest/virt/kvm/cpuid.html
	for i := 0; i < int(cpuid.Nent); i++ {
		if cpuid.Entries[i].Function != kvm.CPUIDSignature {
			continue
		}

		cpuid.Entries[i].Eax = kvm.CPUIDFeatures
		cpuid.Entries[i].Ebx = 0x4b4d564b // KVMK
		cpuid.Entries[i].Ecx = 0x564b4d56 // VMKV
		cpuid.Entries[i].Edx = 0x4d       // M
	}

	if err := kvm.SetCPUID2(m.vcpuFd, &cpuid); err != nil {
		return err
	}

	return nil
}

func (m *Machine) RunInfiniteLoop() error {
	for {
		isContinute, err := m.RunOnce()
		if err != nil {
			return err
		}

		if !isContinute {
			return nil
		}
	}
}

func (m *Machine) RunOnce() (bool, error) {
	if err := kvm.Run(m.vcpuFd); err != nil {
		// When a signal is sent to the thread hosting the VM it will result in EINTR
		// refs https://gist.github.com/mcastelino/df7e65ade874f6890f618dc51778d83a
		if m.run.ExitReason == kvm.EXITINTR {
			return true, nil
		}

		return false, err
	}

	switch m.run.ExitReason {
	case kvm.EXITHLT:
		fmt.Println("KVM_EXIT_HLT")

		return false, nil
	case kvm.EXITIO:
		direction, size, port, count, offset := m.run.IO()
		f := m.ioportHandlers[port][direction]
		bytes := (*(*[100]byte)(unsafe.Pointer(uintptr(unsafe.Pointer(m.run)) + uintptr(offset))))[0:size]

		for i := 0; i < int(count); i++ {
			if err := f(m, port, bytes); err != nil {
				return false, err
			}
		}

		return true, nil
	default:
		return false, fmt.Errorf("%w: %d", kvm.ErrorUnexpectedEXITReason, m.run.ExitReason)
	}
}

func (m *Machine) initIOPortHandlers() {
	funcNone := func(m *Machine, port uint64, bytes []byte) error {
		return nil
	}

	funcError := func(m *Machine, port uint64, bytes []byte) error {
		return fmt.Errorf("%w: unexpected io port 0x%x", kvm.ErrorUnexpectedEXITReason, port)
	}

	// default handler
	for port := 0; port < 0x10000; port++ {
		for dir := kvm.EXITIOIN; dir <= kvm.EXITIOOUT; dir++ {
			m.ioportHandlers[port][dir] = funcError
		}
	}

	for dir := kvm.EXITIOIN; dir <= kvm.EXITIOOUT; dir++ {
		// VGA
		for port := 0x3c0; port <= 0x3da; port++ {
			m.ioportHandlers[port][dir] = funcNone
		}

		for port := 0x3b4; port <= 0x3b5; port++ {
			m.ioportHandlers[port][dir] = funcNone
		}

		// CMOS clock
		for port := 0x70; port <= 0x71; port++ {
			m.ioportHandlers[port][dir] = funcNone
		}

		// DMA Page Registers (Commonly 74L612 Chip)
		for port := 0x80; port <= 0x9f; port++ {
			m.ioportHandlers[port][dir] = funcNone
		}

		// Serial port 2
		for port := 0x2f8; port <= 0x2ff; port++ {
			m.ioportHandlers[port][dir] = funcNone
		}

		// Serial port 3
		for port := 0x3e8; port <= 0x3ef; port++ {
			m.ioportHandlers[port][dir] = funcNone
		}

		// Serial port 4
		for port := 0x2e8; port <= 0x2ef; port++ {
			m.ioportHandlers[port][dir] = funcNone
		}
	}

	// PS/2 Keyboard (Always 8042 Chip)
	for port := 0x60; port <= 0x6f; port++ {
		m.ioportHandlers[port][kvm.EXITIOIN] = func(m *Machine, port uint64, bytes []byte) error {
			// In ubuntu 20.04 on wsl2, the output to IO port 0x64 continued
			// infinitely. To deal with this issue, refer to kvmtool and
			// configure the input to the Status Register of the PS2 controller.
			//
			// refs:
			// https://github.com/kvmtool/kvmtool/blob/0e1882a49f81cb15d328ef83a78849c0ea26eecc/hw/i8042.c#L312
			// https://git.kernel.org/pub/scm/linux/kernel/git/will/kvmtool.git/tree/hw/i8042.c#n312
			// https://wiki.osdev.org/%228042%22_PS/2_Controller
			bytes[0] = 0x20

			return nil
		}
		m.ioportHandlers[port][kvm.EXITIOOUT] = funcNone
	}

	// Serial port 1
	for port := serial.COM1Addr; port < serial.COM1Addr+8; port++ {
		m.ioportHandlers[port][kvm.EXITIOIN] = func(m *Machine, port uint64, bytes []byte) error {
			return m.serial.In(port, bytes)
		}
		m.ioportHandlers[port][kvm.EXITIOOUT] = func(m *Machine, port uint64, bytes []byte) error {
			return m.serial.Out(port, bytes)
		}
	}
}
