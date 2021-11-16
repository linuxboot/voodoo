package services

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/trace"
	"github.com/linuxboot/voodoo/uefi"
)

// Runtime implements Service
type Runtime struct {
	u  ServBase
	up ServPtr
}

func init() {
	RegisterCreator("runtime", NewRuntime)
}

// NewRuntime returns a Runtime Service
func NewRuntime(tab []byte, u ServPtr) (Service, error) {
	Debug("runtime services table u is %#x", u)
	base := int(u) & 0xffffff
	for p := range table.RuntimeServicesNames {
		InstallUEFICall(tab, base, p)
	}

	return &Runtime{u: u.Base(), up: u}, nil
}

// Aliases implements Aliases
func (r *Runtime) Aliases() []string {
	return nil
}

// Base implements service.Base
func (r *Runtime) Base() ServBase {
	return r.u
}

// Base implements service.Ptr
func (r *Runtime) Ptr() ServPtr {
	return r.up
}

// Call implements service.Call
func (r *Runtime) Call(f *Fault) error {
	op := f.Op
	t, ok := table.RuntimeServicesNames[uint64(op)]
	if !ok {
		log.Panicf("runtimeservices Call No such op %#x", op)
	}
	Debug("runtimeservices Call: %s(%#x), arg type %T, args %v", t, op, f.Inst.Args, f.Inst.Args)
	switch op {
	case table.RTGetVariable:
		args := trace.Args(f.Proc, f.Regs, 5)
		Debug("table.RTGetVariable args %#x", args)
		ptr := args[0]
		n, err := trace.ReadStupidString(f.Proc, ptr)
		if err != nil {
			return fmt.Errorf("Can't read StupidString at #%x, err %v", ptr, err)
		}
		var g guid.GUID
		if err := f.Proc.Read(args[1], g[:]); err != nil {
			return fmt.Errorf("Can't read guid at #%x, err %v", args[1], err)
		}
		Debug("PCHandleProtocol: find %s %s", n, g)
		f.SetEFIRetval(uefi.EFI_SUCCESS)
		v, err := uefi.ReadVariable(n, g)
		if err != nil {
			f.SetEFIRetval(uefi.EFI_NOT_FOUND)
			if err := f.Proc.SetRegs(f.Regs); err != nil {
				return err
			}
		}
		Debug("%s:%s: v is %v", n, g, v)
	case table.RTSetVariable:
		f.SetEFIRetval(uefi.EFI_SUCCESS)
		// whatever.
	case table.RTGetTime:
		args := trace.Args(f.Proc, f.Regs, 2)
		Debug("table.RTGetTime args %#x", args)
		now := time.Now()
		if args[0] != 0 {
			var b = &bytes.Buffer{}
			if err := binary.Write(b, binary.LittleEndian, &table.EfiTime{
				Year:       uint16(now.Year()),
				Month:      uint8(now.Month()),
				Day:        uint8(now.Day()),
				Hour:       uint8(now.Hour()),
				Minute:     uint8(now.Minute()),
				Second:     uint8(now.Second()),
				Nanosecond: uint32(now.Nanosecond()),
				//Timezone: now.Timezone(),
				Daylight: 1, // uefi.EFI_TIME_ADJUST_DAYLIGHT, //now.Daylight()?
				//        if (tm.tm_isdst > 0)
				// time->daylight |= EFI_TIME_IN_DAYLIGHT;
				Timezone: 0, //uefi.EFI_UNSPECIFIED_TIMEZONE,
			}); err != nil {
				log.Fatalf("Can't encode memory: %v", err)
			}
			if err := f.Proc.Write(args[0], b.Bytes()); err != nil {
				return fmt.Errorf("Can't write %d bytes to %#x: %v", b.Len(), dat, err)
			}
		}
		if args[1] != 0 {
			// Set reasonable dummy values  -- most appropriate for UEFI
			var b = &bytes.Buffer{}
			if err := binary.Write(b, binary.LittleEndian, &table.EfiTimeCap{
				Resolution: 1,         // 1 Hz
				Accuracy:   100000000, // 100 ppm
				SetsToZero: 0,
			}); err != nil {
				log.Fatalf("Can't encode memory: %v", err)
			}
			if err := f.Proc.Write(args[1], b.Bytes()); err != nil {
				return fmt.Errorf("Can't write %d bytes to %#x: %v", b.Len(), dat, err)
			}
		}
		f.SetEFIRetval(uefi.EFI_SUCCESS)

	default:
		log.Panicf("fix me: %s(%#x): %s", table.RuntimeServicesNames[uint64(op)], op, string(debug.Stack()))
		f.SetEFIRetval(uefi.EFI_UNSUPPORTED)
	}
	return nil
}

// OpenProtocol implements service.OpenProtocol
func (r *Runtime) OpenProtocol(f *Fault, h *Handle, g guid.GUID, ptr uintptr, ah, ch *Handle, attr uintptr) (*dispatch, error) {
	log.Panicf("here we are")
	return nil, fmt.Errorf("not yet")
}
