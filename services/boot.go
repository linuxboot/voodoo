package services

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/ptrace"
	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
)

// Boot implements Service
type Boot struct {
	u ServBase
}

func init() {
	RegisterCreator("boot", NewBoot)
}

// NewBoot returns a Boot Service
func NewBoot(u ServBase) (Service, error) {
	return &Boot{u: u}, nil
}

// Base implements service.Base
func (r *Boot) Base() ServBase {
	return r.u
}

// Call implements service.Call
func (r *Boot) Call(f *Fault) error {
	op := f.Op
	log.Printf("Boot services: %s(%#x), arg type %T, args %v", table.BootServicesNames[int(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {

	case table.AllocatePool:
		// Status = gBS->AllocatePool (EfiBootServicesData, sizeof (EXAMPLE_DEVICE), (VOID **)&Device);
		f.Args = ptrace.Args(f.Proc, f.Regs, 5)
		// ignore arg 0 for now.
		log.Printf("AllocatePool: %d bytes", f.Args[1])
		var bb [4]byte
		binary.LittleEndian.PutUint32(bb[:], uint32(dat))
		if err := f.Proc.Write(f.Args[2], bb[:]); err != nil {
			return fmt.Errorf("Can't write %d bytes to %#x: %v", len(bb), dat, err)
		}
		dat += f.Args[1]
		return nil
	case table.FreePool:
		// Status = gBS->FreePool (Device);
		f.Args = ptrace.Args(f.Proc, f.Regs, 1)
		// Free? Forget it.
		log.Printf("FreePool: %#x", f.Args[0])
		return nil
	case table.LocateHandle:
		// EFI_STATUS LocateHandle (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID *Protocol OPTIONAL, IN VOID *SearchKey OPTIONAL,IN OUT UINTN *NoHandles,  OUT EFI_HANDLE **Buffer);
		// We had hoped to ignore this nonsense, but ... we can't
		f.Args = ptrace.Args(f.Proc, f.Regs, 5)

		var g guid.GUID
		if err := f.Proc.Read(f.Args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", f.Args[1], err)
		}

		log.Printf("BootServices Call LocateHandle(type %s, guid %s, searchkey %#x, nohandles %#x, EFIHANDLE %#x", table.SearchTypeNames[table.EFI_LOCATE_SEARCH_TYPE(f.Args[0])], g, f.Args[2], f.Args[3], f.Args[4])
		// This is probably done wrong, the way we do this. Oh well.
		// I think ServBase should just be a string.
		b, ok := dispatchService[g.String()]
		if !ok {
			return fmt.Errorf("No registered service for %s", g)
		}

		d, ok := dispatches[b]
		if !ok {
			log.Panicf("Can't happen: no base for %s", g)
		}
		log.Printf("Writing %#x to args[4]", d.base)
		var bb [4]byte
		binary.LittleEndian.PutUint64(bb[:], uint64(d.base))
		if err := f.Proc.Write(f.Args[4], bb[:]); err != nil {
			return fmt.Errorf("Can't write %v to %#x: %v", d, f.Args[4], err)
		}
		binary.LittleEndian.PutUint64(bb[:], uint64(1))
		if err := f.Proc.Write(f.Args[3], bb[:]); err != nil {
			return fmt.Errorf("Can't write %v to %#x: %v", d, f.Args[3], err)
		}
		return nil
	case table.HandleProtocol:
		// There. All on one line. Not 7. So, UEFI, did that really hurt so much?
		// typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface);

		// The arguments are rcx, rdx, r9
		f.Args = ptrace.Args(f.Proc, f.Regs, 3)
		var g guid.GUID
		if err := f.Proc.Read(f.Args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", f.Args[1], err)
		}
		log.Printf("HandleProtocol: GUID %s", g)
		b, ok := dispatchService[g.String()]
		if !ok {
			return fmt.Errorf("No registered service for %s", g)
		}

		d, ok := dispatches[b]
		if !ok {
			return fmt.Errorf("Can't happen: no base for %s", g)
		}
		var bb [4]byte
		binary.LittleEndian.PutUint32(bb[:], uint32(dat))
		if err := f.Proc.Write(f.Args[2], bb[:]); err != nil {
			return fmt.Errorf("Can't write %v to %#x: %v", d, f.Args[2], err)
		}
		fmt.Printf("OK all done handleprotocol")
		return nil
	case table.PCHandleProtocol:
		// There. All on one line. Not 7. So, UEFI, did that really hurt so much?
		// typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface);

		// The arguments are rcx, rdx, r9
		f.Args = ptrace.Args(f.Proc, f.Regs, 3)
		var g guid.GUID
		if err := f.Proc.Read(f.Args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", f.Args[1], err)
		}
		log.Printf("PCHandleProtocol: GUID %s", g)

		return nil
	case table.ConnectController:
		// The arguments are rcx, rdx, r9, r8
		f.Args = ptrace.Args(f.Proc, f.Regs, 4)
		log.Printf("ConnectController: %#x", f.Args)
		// Just pretend it worked.
		return nil
	case table.WaitForEvent:
		f.Args = ptrace.Args(f.Proc, f.Regs, 3)
		log.Printf("WaitForEvent: %#x", f.Args)
		// Just pretend it worked.
		return nil
	default:
		log.Panic("unsupported boot service")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}

// Load implements service.Load
func (r *Boot) Load(f *Fault) error {
	f.Regs.Rax = uefi.EFI_SUCCESS
	op := f.Op
	t, ok := table.BootServicesNames[int(op)]
	if !ok {
		log.Panicf("unsupported Boot Load of %#x", op)
	}
	ret := uintptr(op) + uintptr(r.u)
	log.Printf("Boot Load services: %v(%#x), arg type %T, args %v return %#x", t, op, f.Inst.Args, f.Inst.Args, ret)
	if err := retval(f, ret); err != nil {
		log.Panic(err)
	}
	return nil
}

// Store implements service.Store
func (r *Boot) Store(f *Fault) error {
	op := f.Op
	log.Printf("Boot Store services: %s(%#x), arg type %T, args %v", table.BootServicesNames[int(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	default:
		log.Panic("unsupported Boot Store")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
