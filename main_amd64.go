// Copyright 2012-2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

var regsprint = []struct {
	name   string
	format string
}{
	{"Rip", "%#x"},
	{"R15", "%016x"},
	{"R14", "%016x"},
	{"R13", "%016x"},
	{"R12", "%016x"},
	{"Rbp", "%016x"},
	{"Rbx", "%016x"},
	{"R11", "%016x"},
	{"R10", "%016x"},
	{"R9", "%016x"},
	{"R8", "%016x"},
	{"Rax", "%016x"},
	{"Rcx", "%016x"},
	{"Rdx", "%016x"},
	{"Rsi", "%016x"},
	{"Rdi", "%016x"},
	{"Orig_rax", "%016x"},
	{"Eflags", "%08x"},
	{"Rsp", "%016x"},
	{"Fs_base", "%016x"},
	{"Gs_base", "%016x"},
	{"Cs", "%04x"},
	{"Ds", "%04x"},
	{"Es", "%04x"},
	{"Fs", "%04x"},
	{"Gs", "%04x"},
	{"Ss", "%04x"},
}
