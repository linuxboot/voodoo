package trace

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"syscall"

	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

// Args returns the top nargs args, going down the stack if needed. The max is 6.
func Args(t Trace, r *syscall.PtraceRegs, nargs int) []uintptr {
	sp := uintptr(r.Rsp)
	switch nargs {
	case 6:
		w1, _ := t.ReadWord(sp + 0x20)
		w2, _ := t.ReadWord(sp + 0x28)
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx), uintptr(r.R8), uintptr(r.R9), uintptr(w1), uintptr(w2)}
	case 5:
		w1, _ := t.ReadWord(sp + 0x20)
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx), uintptr(r.R8), uintptr(r.R9), uintptr(w1)}
	case 4:
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx), uintptr(r.R8), uintptr(r.R9)}
	case 3:
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx), uintptr(r.R8)}
	case 2:
		return []uintptr{uintptr(r.Rcx), uintptr(r.Rdx)}
	case 1:
		return []uintptr{uintptr(r.Rcx)}
	}
	return []uintptr{}
}

// Pointer returns the data pointed to by args[arg]
func Pointer(t Trace, inst *x86asm.Inst, r *syscall.PtraceRegs, arg int) (uintptr, error) {
	m := inst.Args[arg].(x86asm.Mem)
	// A Mem is a memory reference.
	// The general form is Segment:[Base+Scale*Index+Disp].
	/*
		type Mem struct {
			Segment Reg
			Base    Reg
			Scale   uint8
			Index   Reg
			Disp    int64
		}
	*/
	Debug("ARG[%d] %q m is %#x", inst.Args[arg], m)
	b, err := GetReg(r, m.Base)
	if err != nil {
		return 0, fmt.Errorf("Can't get Base reg %v in %v", m.Base, m)
	}
	addr := *b + uint64(m.Disp)
	x, err := GetReg(r, m.Index)
	if err == nil {
		addr += uint64(m.Scale) * (*x)
	}
	//if v, ok := inst.Args[0].(*x86asm.Mem); ok {
	Debug("computed addr is %#x", addr)
	return uintptr(addr), nil
}

// Pop pops the stack and returns what was at TOS.
func Pop(t Trace, r *syscall.PtraceRegs) (uint64, error) {
	cpc, err := t.ReadWord(uintptr(r.Rsp))
	if err != nil {
		return 0, err
	}
	r.Rsp += 8
	return cpc, nil
}

// GetReg gets a register value from the Tracee.
// This code does not do any ptrace calls to get registers.
// It returns a pointer so the register can be read and modified.
func GetReg(r *syscall.PtraceRegs, reg x86asm.Reg) (*uint64, error) {
	Debug("GetReg %s", reg)
	switch reg {
	case x86asm.AL:
	case x86asm.CL:
	case x86asm.DL:
	case x86asm.BL:
	case x86asm.AH:
	case x86asm.CH:
	case x86asm.DH:
	case x86asm.BH:
	case x86asm.SPB:
	case x86asm.BPB:
	case x86asm.SIB:
	case x86asm.DIB:
	case x86asm.R8B:
	case x86asm.R9B:
	case x86asm.R10B:
	case x86asm.R11B:
	case x86asm.R12B:
	case x86asm.R13B:
	case x86asm.R14B:
	case x86asm.R15B:

	// 16-bit
	case x86asm.AX:
	case x86asm.CX:
	case x86asm.DX:
	case x86asm.BX:
	case x86asm.SP:
	case x86asm.BP:
	case x86asm.SI:
	case x86asm.DI:
	case x86asm.R8W:
	case x86asm.R9W:
	case x86asm.R10W:
	case x86asm.R11W:
	case x86asm.R12W:
	case x86asm.R13W:
	case x86asm.R14W:
	case x86asm.R15W:

	// 32-bit
	case x86asm.EAX:
	case x86asm.ECX:
	case x86asm.EDX:
	case x86asm.EBX:
	case x86asm.ESP:
	case x86asm.EBP:
	case x86asm.ESI:
	case x86asm.EDI:
	case x86asm.R8L:
	case x86asm.R9L:
	case x86asm.R10L:
	case x86asm.R11L:
	case x86asm.R12L:
	case x86asm.R13L:
	case x86asm.R14L:
	case x86asm.R15L:

	// 64-bit
	case x86asm.RAX:
		return &r.Rax, nil
	case x86asm.RCX:
		return &r.Rcx, nil
	case x86asm.RDX:
		return &r.Rdx, nil
	case x86asm.RBX:
		return &r.Rbx, nil
	case x86asm.RSP:
		return &r.Rsp, nil
	case x86asm.RBP:
		return &r.Rbp, nil
	case x86asm.RSI:
		return &r.Rsi, nil
	case x86asm.RDI:
		return &r.Rdi, nil
	case x86asm.R8:
		return &r.R8, nil
	case x86asm.R9:
		return &r.R9, nil
	case x86asm.R10:
		return &r.R10, nil
	case x86asm.R11:
		return &r.R11, nil
	case x86asm.R12:
		return &r.R12, nil
	case x86asm.R13:
		return &r.R13, nil
	case x86asm.R14:
		return &r.R14, nil
	case x86asm.R15:
		return &r.R15, nil
	case x86asm.RIP:
		return &r.Rip, nil
	// Instruction pointer.
	case x86asm.IP: // 16-bit:
	case x86asm.EIP: // 32-bit:

	// 387 floating point registers.
	case x86asm.F0:
	case x86asm.F1:
	case x86asm.F2:
	case x86asm.F3:
	case x86asm.F4:
	case x86asm.F5:
	case x86asm.F6:
	case x86asm.F7:

	// MMX registers.
	case x86asm.M0:
	case x86asm.M1:
	case x86asm.M2:
	case x86asm.M3:
	case x86asm.M4:
	case x86asm.M5:
	case x86asm.M6:
	case x86asm.M7:

	// XMM registers.
	case x86asm.X0:
	case x86asm.X1:
	case x86asm.X2:
	case x86asm.X3:
	case x86asm.X4:
	case x86asm.X5:
	case x86asm.X6:
	case x86asm.X7:
	case x86asm.X8:
	case x86asm.X9:
	case x86asm.X10:
	case x86asm.X11:
	case x86asm.X12:
	case x86asm.X13:
	case x86asm.X14:
	case x86asm.X15:

	// Segment registers.
	case x86asm.ES:
	case x86asm.CS:
	case x86asm.SS:
	case x86asm.DS:
	case x86asm.FS:
	case x86asm.GS:

	// System registers.
	case x86asm.GDTR:
	case x86asm.IDTR:
	case x86asm.LDTR:
	case x86asm.MSW:
	case x86asm.TASK:

	// Control registers.
	case x86asm.CR0:
	case x86asm.CR1:
	case x86asm.CR2:
	case x86asm.CR3:
	case x86asm.CR4:
	case x86asm.CR5:
	case x86asm.CR6:
	case x86asm.CR7:
	case x86asm.CR8:
	case x86asm.CR9:
	case x86asm.CR10:
	case x86asm.CR11:
	case x86asm.CR12:
	case x86asm.CR13:
	case x86asm.CR14:
	case x86asm.CR15:

	// Debug registers.
	case x86asm.DR0:
	case x86asm.DR1:
	case x86asm.DR2:
	case x86asm.DR3:
	case x86asm.DR4:
	case x86asm.DR5:
	case x86asm.DR6:
	case x86asm.DR7:
	case x86asm.DR8:
	case x86asm.DR9:
	case x86asm.DR10:
	case x86asm.DR11:
	case x86asm.DR12:
	case x86asm.DR13:
	case x86asm.DR14:
	case x86asm.DR15:

	// Task registers.
	case x86asm.TR0:
	case x86asm.TR1:
	case x86asm.TR2:
	case x86asm.TR3:
	case x86asm.TR4:
	case x86asm.TR5:
	case x86asm.TR6:
	case x86asm.TR7:
	}

	return nil, fmt.Errorf("Can get %v", reg)
}

// ReadStupidString reads a UEFI-style string, i.e. one composed of words, not bytes.
// We're gonna party like it's 1899.
func ReadStupidString(t Trace, address uintptr) (string, error) {
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

// Header prints out a header register.
func Header(w io.Writer) error {
	var l string
	for _, r := range RegsPrint {
		l += fmt.Sprintf("%s%s,", r.name, r.extra)
	}
	_, err := fmt.Fprint(w, l+"\n")
	return err
}

// Regs prints out registers as .csv.
func Regs(w io.Writer, r *syscall.PtraceRegs) error {
	rr := reflect.ValueOf(r).Elem()
	var l string
	for _, rp := range RegsPrint {
		rf := rr.FieldByName(rp.name)
		l += fmt.Sprintf("\""+rp.format+"\",", rf.Interface())
	}
	_, err := fmt.Fprint(w, l)
	return err
}

// RegDiff compares to PtraceRegs and prints out only the ones that have changed, as .csv
func RegDiff(w io.Writer, r, p *syscall.PtraceRegs) error {
	rr := reflect.ValueOf(r).Elem()
	pp := reflect.ValueOf(p).Elem()

	var l string
	for _, rp := range RegsPrint {
		rf := rr.FieldByName(rp.name)
		pf := pp.FieldByName(rp.name)
		rv := fmt.Sprintf(rp.format, rf.Interface())
		pv := fmt.Sprintf(rp.format, pf.Interface())
		if rv != pv {
			l += "\"" + rv + "\""
		}
		l += ","
	}
	_, err := fmt.Fprint(w, l)
	return err
}

type rprint struct {
	name   string
	format string
	extra  string
}

var (
	// GenregsPrint is for general purpose registers.
	GenregsPrint = []rprint{
		{name: "Rip", format: "%#x"},
		{name: "R15", format: "%016x"},
		{name: "R14", format: "%016x"},
		{name: "R13", format: "%016x"},
		{name: "R12", format: "%016x"},
		{name: "Rbp", format: "%016x"},
		{name: "Rbx", format: "%016x"},
		{name: "R11", format: "%016x"},
		{name: "R10", format: "%016x"},
		{name: "R9", format: "%016x", extra: "/A3"},
		{name: "R8", format: "%016x", extra: "/A2"},
		{name: "Rax", format: "%016x"},
		{name: "Rcx", format: "%016x", extra: "/A0"},
		{name: "Rdx", format: "%016x", extra: "/A1"},
		{name: "Rsi", format: "%016x"},
		{name: "Rdi", format: "%016x"},
		{name: "Orig_rax", format: "%016x"},
		{name: "Eflags", format: "%08x"},
		{name: "Rsp", format: "%016x"},
	}
	// AllregsPrint is for all registers, even useless ones.
	AllregsPrint = append(GenregsPrint,
		[]rprint{
			{name: "Fs_base", format: "%016x"},
			{name: "Gs_base", format: "%016x"},
			{name: "Cs", format: "%04x"},
			{name: "Ds", format: "%04x"},
			{name: "Es", format: "%04x"},
			{name: "Fs", format: "%04x"},
			{name: "Gs", format: "%04x"},
			{name: "Ss", format: "%04x"},
		}...)
	// RegsPrint allows for selecting which regs to print
	RegsPrint = GenregsPrint
)

// Inst retrieves an instruction from the traced process.
// It returns an x86asm.Inst, Ptraceregs, a string in GNU syntax, and
// and error
// It gets messy if the Rip is in unaddressable space; that means we
// must fetch the saved Rip from [Rsp].
func Inst(t Trace) (*x86asm.Inst, *syscall.PtraceRegs, string, error) {
	r, err := t.GetRegs()
	if err != nil {
		return nil, nil, "", fmt.Errorf("Inst:Getregs:%v", err)
	}
	pc := r.Rip
	sp := r.Rsp
	Debug("Inst: pc %#x, sp %#x", pc, sp)
	// We maintain all the function pointers in non-addressable space for now.
	// It is in the classic BIOS space.
	if r.Rip > 0xff000000 {
		cpc, err := t.ReadWord(uintptr(sp))
		if err != nil {
			return nil, nil, "", fmt.Errorf("Inst:ReadWord at %#x::%v", sp, err)
		}
		Debug("cpc is %#x from sp", cpc)
		// what a hack.
		if cpc == 0x100000 {
			return nil, nil, "", io.EOF
		}
		var call [5]byte
		if err := t.Read(uintptr(cpc-5), call[:]); err != nil {
			return nil, nil, "", fmt.Errorf("Can' read PC at #%x, err %v", pc, err)
		}

		// It's simple, if call[0] is 0xff, it's 5 bytes, else if call[2] is 0xff, it's 3,
		// else we're screwed.
		switch {
		case call[0] == 0xff:
			cpc -= 5
		case call[2] == 0xff:
			cpc -= 3
		case call[3] == 0xff:
			cpc -= 2
		default:
			return nil, nil, "", fmt.Errorf("Can't interpret call @ %#x: %#x", cpc-5, call)
		}
		pc = cpc
	}
	// We know the PC; grab a bunch of bytes there, then decode and print
	insn := make([]byte, 16)
	if err := t.Read(uintptr(pc), insn); err != nil {
		return nil, nil, "", fmt.Errorf("Can' read PC at #%x, err %v", pc, err)
	}
	d, err := x86asm.Decode(insn, 64)
	if err != nil {
		return nil, nil, "", fmt.Errorf("Can't decode %#02x: %v", insn, err)
	}
	return &d, r, x86asm.GNUSyntax(d, uint64(r.Rip), nil), nil
}

// Disasm returns a string for the disassembled instruction.
func Disasm(t Trace) (string, error) {
	d, _, g, err := Inst(t)
	if err != nil {
		return "", fmt.Errorf("Can't decode %#02x: %v", d, err)
	}
	return g, nil
}

// Asm returns a string for the given instruction at the given pc
func Asm(d *x86asm.Inst, pc uint64) string {
	return "\"" + x86asm.GNUSyntax(*d, pc, nil) + "\""
}

func showone(indent string, in interface{}) string {
	var ret string
	s := reflect.ValueOf(in).Elem()
	typeOfT := s.Type()

	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		switch f.Kind() {
		case reflect.String:
			ret += fmt.Sprintf(indent+"%s %s = %s\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
		default:
			ret += fmt.Sprintf(indent+"%s %s = %#x\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
		}
	}
	return ret
}

func show(indent string, l ...interface{}) string {
	var ret string
	for _, i := range l {
		ret += showone(indent, i)
	}
	return ret
}

// CallInfo provides calling info for a function.
func CallInfo(_ *unix.SignalfdSiginfo, inst *x86asm.Inst, r *syscall.PtraceRegs) string {
	l := fmt.Sprintf("%s[", show("", r))
	for _, a := range inst.Args {
		l += fmt.Sprintf("%v,", a)
	}
	l += fmt.Sprintf("(%#x, %#x, %#x, %#x)", r.Rcx, r.Rdx, r.R8, r.R9)
	return l
}

// WriteWord writes the given word into the inferior's address space.
func WriteWord(t Trace, address uintptr, word uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], word)
	return t.Write(address, b[:])
}

// ReadWord reads the given word from the inferior's address space.
func ReadWord(t Trace, address uintptr) (uint64, error) {
	var b [8]byte
	if err := t.Read(address, b[:]); err != nil {
		return 0, err
	}
	var w uint64
	w = binary.LittleEndian.Uint64(b[:])
	return w, nil
}
