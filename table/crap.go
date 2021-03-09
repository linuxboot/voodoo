package table

// All the crap that goes nowhere else.

type EFI_LOCATE_SEARCH_TYPE uint32

const (
	AllHandles       EFI_LOCATE_SEARCH_TYPE = 0
	ByRegisterNotify EFI_LOCATE_SEARCH_TYPE = 1
	ByProtocol       EFI_LOCATE_SEARCH_TYPE = 2
)

var SearchTypeNames = map[EFI_LOCATE_SEARCH_TYPE]string{
	AllHandles:       "AllHandles",
	ByRegisterNotify: "ByRegisterNotify",
	ByProtocol:       "ByProtocol",
}
