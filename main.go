package main

import (
	"fmt"
	"log"
	"reflect"

	"github.com/tfogal/ptrace"
)

func main() {
	t, err := ptrace.Exec("a", []string{"a"})
	if err != nil {
		log.Fatal(err)
	}
	for e := range t.Events() {
		fmt.Printf("Event: %v, ", e)
		r, err := t.GetRegs()
		if err != nil {
			log.Printf("Could not get regs: %v", err)
		}
		pc, err := t.GetIPtr()
		if err != nil {
			log.Printf("Could not get pc: %v", err)
		}
		fmt.Printf("PC %#x\n", pc)
		s := reflect.ValueOf(&r).Elem()
		typeOfT := s.Type()

		for i := 0; i < s.NumField(); i++ {
			f := s.Field(i)
			fmt.Printf("\t%s %s = %v\n", typeOfT.Field(i).Name, f.Type(), f.Interface())
		}
		if err := t.SingleStep(); err != nil {
			log.Print(err)
		}
	}
}
