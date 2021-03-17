package trace

// SetIPtr sets the instruction pointer for a Tracee.
func SetIPtr(t Trace, addr uintptr) error {
	r, err := t.GetRegs()
	if err != nil {
		return err
	}
	r.Rip = uint64(addr)
	return t.SetRegs(r)
}
