package table

type OpenProtocolAttributes uint32

const (
	EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL  = 0x00000001
	EFI_OPEN_PROTOCOL_GET_PROTOCOL        = 0x00000002
	EFI_OPEN_PROTOCOL_TEST_PROTOCOL       = 0x00000004
	EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER = 0x00000008
	EFI_OPEN_PROTOCOL_BY_DRIVER           = 0x00000010
	EFI_OPEN_PROTOCOL_EXCLUSIVE           = 0x00000020
)

func (o *OpenProtocolAttributes) String() string {
	var s string
	switch int(*o) & 0x1f {
	case EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL:
		s = "EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL"
	case EFI_OPEN_PROTOCOL_GET_PROTOCOL:
		s = "EFI_OPEN_PROTOCOL_GET_PROTOCOL"
	case EFI_OPEN_PROTOCOL_TEST_PROTOCOL:
		s = "EFI_OPEN_PROTOCOL_TEST_PROTOCOL"
	case EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER:
		s = "EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER"
	case EFI_OPEN_PROTOCOL_BY_DRIVER:
		s = "EFI_OPEN_PROTOCOL_BY_DRIVER"
	}

	if int(*o)&EFI_OPEN_PROTOCOL_EXCLUSIVE != 0 {
		s += "(exclusive)"
	}
	return s
}
