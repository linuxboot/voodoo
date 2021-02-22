package services

import "log"

// Func is a function selector.
type Func uint16

// Service is the interface to services.
type Service interface {
	Call(f Func) error
}

type serviceCreator func(b uintptr) (Service, error)

var services = map[string]serviceCreator{}

// Register registers services.
func Register(n string, s serviceCreator) {
	if _, ok := services[n]; ok {
		log.Fatalf("Register: %s is already registered", n)
	}
	services[n] = s
}
