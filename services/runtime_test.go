package services

import (
	"syscall"
	"testing"

	"github.com/linuxboot/voodoo/table"
	"github.com/linuxboot/voodoo/uefi"
	"golang.org/x/arch/x86/x86asm"
)

func TestNew(t *testing.T) {
	r, err := NewRuntime(servBaseName(0x1abcde))
	if err != nil {
		t.Fatalf("NewRuntime: got %v, want nil", err)
	}
	f := &Fault{Args: []uintptr{1, 2, 3}, Regs: &syscall.PtraceRegs{}, Inst: &x86asm.Inst{Args: x86asm.Args{}}, Op: table.RTSetVariable, Asm: "CALL x"}

	if err := r.Call(f); err != nil {
		t.Fatalf("Call with bad value: got %v, want nil", err)
	}
	if f.Regs.Rax != uefi.EFI_SUCCESS {
		t.Fatalf("Call with bad value: got f.Regs.Rax %v, want %v", f.Regs.Rax, uefi.EFI_SUCCESS)
	}
}
