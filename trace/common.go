package trace

import (
	"fmt"
	"io"
	"reflect"
	"syscall"
)

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

// Disasm returns a string for the disassembled instruction.
func Disasm(t Trace) (string, error) {
	d, _, g, err := Inst(t)
	if err != nil {
		return "", fmt.Errorf("Can't decode %#02x: %v", d, err)
	}
	return g, nil
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
