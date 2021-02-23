package services

var (
	dat uintptr
)

func SetAllocator(b, lim uintptr) {
	dat = b
}
