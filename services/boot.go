package services

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/trace"
	"github.com/linuxboot/voodoo/uefi"
)

// Boot implements Service
type Boot struct {
	u  ServBase
	up ServPtr
}

func init() {
	RegisterCreator("boot", NewBoot)
}

// NewBoot returns a Boot Service
func NewBoot(tab []byte, u ServPtr) (Service, error) {
	// Put the pointer for one thing to see what happens.
	Debug("boot services table u is %#x", u)
	base := int(u) & 0xffffff
	for p := range table.BootServicesNames {
		x := base + int(p)
		r := uint64(p) + 0xff400000 + uint64(base)
		Debug("Install %#x at off %#x", r, x)
		binary.LittleEndian.PutUint64(tab[x:], uint64(r))
	}

	return &Boot{u: u.Base(), up: u}, nil
}

func (r *Boot) SetFun(t trace.Trace) error {
	if err := trace.WriteWord(t, uintptr(r.up)+0x98, uint64(r.up)+0x400000); err != nil {
		return err
	}
	return nil
}

// Base implements service.Base
func (r *Boot) Base() ServBase {
	return r.u
}

// Base implements service.Ptr
func (b *Boot) Ptr() ServPtr {
	return b.up
}

// Call implements service.Call
func (r *Boot) Call(f *Fault) error {
	op := f.Op
	f.Regs.Rax = uefi.EFI_SUCCESS
	Debug("Boot services: %s(%#x), arg type %T, args %v", table.BootServicesNames[int(op)], op, f.Inst.Args, f.Inst.Args)
	switch op {
	case table.GetMemoryMap:
		// EFI_STATUS efi_get_memorymap(IN OUT UINTN *MemoryMapSize, IN OUT EFI_MEMORY_DESCRIPTOR *MemoryMap, ...);
		// Go simple for now. You own 2G. That's all you own.
		var b = &bytes.Buffer{}
		if err := binary.Write(b, binary.LittleEndian, &uefi.MemRegion{
			MType:  uefi.EfiConventionalMemory,
			PA:     0,
			VA:     0,
			Npages: 0x20000000 / 0x1000,
			Attr:   uefi.All,
		}); err != nil {
			log.Fatalf("Can't encode memory: %v", err)
		}
		f.Args = trace.Args(f.Proc, f.Regs, 2)
		Debug("GetMemoryMap: %#x", f.Args)
		// Just one region.
		var bb = [8]byte{1}
		if err := f.Proc.Write(f.Args[0], bb[:]); err != nil {
			return fmt.Errorf("Can't write %d bytes to %#x: %v", len(bb), dat, err)
		}
		if err := f.Proc.Write(f.Args[1], b.Bytes()); err != nil {
			return fmt.Errorf("Can't write %d bytes to %#x: %v", len(bb), dat, err)
		}
		return nil
	case table.AllocatePool:
		// Status = gBS->AllocatePool (EfiBootServicesData, sizeof (EXAMPLE_DEVICE), (VOID **)&Device);
		f.Args = trace.Args(f.Proc, f.Regs, 5)
		// ignore arg 0 for now.
		d := uint64(UEFIAllocate(uintptr(f.Args[1]), false))
		Debug("AllocatePool: %d bytes @ %#x", f.Args[1], d)
		var bb [8]byte
		binary.LittleEndian.PutUint64(bb[:], d)
		if err := f.Proc.Write(f.Args[2], bb[:]); err != nil {
			return fmt.Errorf("Can't write %d bytes to %#x: %v", len(bb), dat, err)
		}
		return nil
	case table.FreePool:
		// Status = gBS->FreePool (Device);
		f.Args = trace.Args(f.Proc, f.Regs, 1)
		// Free? Forget it.
		Debug("FreePool: %#x", f.Args[0])
		return nil
	case table.AllocatePages:
		//Status = gBS->AllocatePages (AllocateAnyPages,EfiBootServicesData,Pages,&PhysicalBuffer);
		f.Args = trace.Args(f.Proc, f.Regs, 4)
		// ignore arg 0 for now.
		d := uint64(UEFIAllocate(uintptr(f.Args[1]*4096), true))
		Debug("AllocatePages %d pages @ %#x", f.Args[1], d)
		var bb [8]byte
		binary.LittleEndian.PutUint64(bb[:], d)
		if err := f.Proc.Write(f.Args[3], bb[:]); err != nil {
			return fmt.Errorf("Can't write %d bytes to %#x: %v", len(bb), dat, err)
		}
		return nil
	case table.FreePages:
		//Status = gBS->AllocatePages (AllocateAnyPages,EfiBootServicesData,Pages,&PhysicalBuffer);
		f.Args = trace.Args(f.Proc, f.Regs, 2)
		Debug("FreePages %#x", f.Args)
		return nil
	case table.LocateHandle:
		// EFI_STATUS LocateHandle (IN EFI_LOCATE_SEARCH_TYPE SearchType, IN EFI_GUID *Protocol OPTIONAL, IN VOID *SearchKey OPTIONAL,IN OUT UINTN *NoHandles,  OUT EFI_HANDLE **Buffer);
		// We had hoped to ignore this nonsense, but ... we can't
		f.Args = trace.Args(f.Proc, f.Regs, 5)
		var g guid.GUID
		if err := f.Proc.Read(f.Args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", f.Args[1], err)
		}

		Debug("BootServices Call LocateHandle(type %s, guid %s, searchkey %#x, numhandles %#x, EFIHANDLE %#x", table.SearchTypeNames[table.EFI_LOCATE_SEARCH_TYPE(f.Args[0])], g, f.Args[2], f.Args[3], f.Args[4])
		d, ok := dispatches[ServBase(g.String())]
		Debug("LocateHandle: GUID %s %v ok? %v", g, d, ok)
		if !ok {
			// If it's not there, we can just return with no error and no handles.
			log.Printf("no base for %s", g)
			f.Regs.Rax = uefi.EFI_NOT_FOUND
			return nil
		}
		Debug("Writing Service %v base %#x to %#x", d, uint64(d.up), f.Args[4])
		var bb [8]byte
		binary.LittleEndian.PutUint64(bb[:], uint64(d.up))
		if err := f.Proc.Write(f.Args[4], bb[:]); err != nil {
			return fmt.Errorf("Can't write %v to %#x: %v", d, f.Args[4], err)
		}
		binary.LittleEndian.PutUint64(bb[:], uint64(table.EfiHandleSize))
		if err := f.Proc.Write(f.Args[3], bb[:]); err != nil {
			return fmt.Errorf("Can't write %v to %#x: %v", d, f.Args[3], err)
		}
		Debug("BootServices Call LocateHandle: done")
		return nil
	case table.HandleProtocol:
		// There. All on one line. Not 7. So, UEFI, did that really hurt so much?
		// typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface);

		// The arguments are rcx, rdx, r9
		f.Args = trace.Args(f.Proc, f.Regs, 3)
		var g guid.GUID
		if err := f.Proc.Read(f.Args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", f.Args[1], err)
		}
		d, ok := dispatches[ServBase(g.String())]
		Debug("HandleProtocol: GUID %s %v ok? %v", g, d, ok)
		if !ok {
			f.Regs.Rax = uefi.EFI_NOT_FOUND
			return nil
		}
		var bb [8]byte
		Debug("Address is %#x", d.up)
		binary.LittleEndian.PutUint64(bb[:], uint64(d.up))
		if err := f.Proc.Write(f.Args[2], bb[:]); err != nil {
			return fmt.Errorf("Can't write %v to %#x: %v", d, f.Args[2], err)
		}
		Debug("OK all done handleprotocol")
		return nil
	case table.PCHandleProtocol:
		// There. All on one line. Not 7. So, UEFI, did that really hurt so much?
		// typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface);

		// The arguments are rcx, rdx, r9
		f.Args = trace.Args(f.Proc, f.Regs, 3)
		var g guid.GUID
		if err := f.Proc.Read(f.Args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", f.Args[1], err)
		}
		Debug("PCHandleProtocol: GUID %s", g)

		return nil
	case table.ConnectController:
		// The arguments are rcx, rdx, r9, r8
		f.Args = trace.Args(f.Proc, f.Regs, 4)
		Debug("ConnectController: %#x", f.Args)
		// Just pretend it worked.
		return nil
	case table.WaitForEvent:
		f.Args = trace.Args(f.Proc, f.Regs, 3)
		Debug("WaitForEvent: %#x", f.Args)
		// Just pretend it worked.
		return nil
	case table.OpenProtocol:
		// This one is a serious shitshow.
		// it's a mess b/c UEFI is a mess.
		// It's a pretty minimal implementation.
		//EFI_STATUS
		//(EFIAPI * EFI_OPEN_PROTOCOL)(
		//  IN EFI_HANDLE  Handle,
		//  IN EFI_GUID                     *Protocol,
		//  OUT VOID                        **Interface, OPTIONAL
		//  IN EFI_HANDLE                   AgentHandle,
		//  IN EFI_HANDLE                   ControllerHandle,
		//  IN UINT32                       Attributes
		//  );
		f.Args = trace.Args(f.Proc, f.Regs, 6)
		Debug("OpenProtocol: %#x", f.Args)
		var g guid.GUID
		if err := f.Proc.Read(f.Args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", f.Args[1], err)
		}
		Debug("OpenProtocol: GUID %s", g)
		d, ok := dispatches[ServBase(g.String())]
		Debug("Openrotocol: GUID %s %v ok? %v", g, d, ok)
		if !ok {
			f.Regs.Rax = uefi.EFI_NOT_FOUND
			return nil
		}
		var bb [8]byte
		Debug("Address is %#x", d.up)
		binary.LittleEndian.PutUint64(bb[:], uint64(d.up))
		if f.Args[2] != 0 {
			if err := f.Proc.Write(f.Args[2], bb[:]); err != nil {
				return fmt.Errorf("Can't write %v to %#x: %v", d, f.Args[2], err)
			}
		}
		Debug("OpenProtocol: done")
	case table.LocateProtocol:
		// Status = gBS->LocateProtocol (GUID,NULL,(VOID **)&ptr);
		f.Args = trace.Args(f.Proc, f.Regs, 3)
		Debug("LocateProtocol: %#x", f.Args)
		var g guid.GUID
		if err := f.Proc.Read(f.Args[0], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", f.Args[1], err)
		}
		Debug("LocateProtocol: GUID %s", g)
		d, ok := dispatches[ServBase(g.String())]
		Debug("HandleProtocol: GUID %s %v ok? %v", g, d, ok)
		if !ok {
			f.Regs.Rax = uefi.EFI_NOT_FOUND
			return nil
		}
		var bb [8]byte
		Debug("Address is %#x", d.up)
		binary.LittleEndian.PutUint64(bb[:], uint64(d.up))
		if err := f.Proc.Write(f.Args[2], bb[:]); err != nil {
			return fmt.Errorf("Can't write %v to %#x: %v", d, f.Args[2], err)
		}
		Debug("OK all done LocateProtocol")
		return nil
	case table.SetWatchdogTimer:
		f.Args = trace.Args(f.Proc, f.Regs, 5)
		Debug("SetWatchdogTimer: %#x", f.Args)
		// Just pretend it worked.
		return nil

	default:
		log.Panic("unsupported boot service")
		f.Regs.Rax = uefi.EFI_UNSUPPORTED
	}
	return nil
}
