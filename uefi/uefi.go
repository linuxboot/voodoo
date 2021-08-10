package uefi

import (
	"fmt"
	"strconv"

	"github.com/linuxboot/fiano/pkg/guid"
)

// All the things we hate about UEFI in one convenient place
const (
	EFI_SUCCESS               = 0
	EFI_LOAD_ERROR            = (1)
	EFI_INVALID_PARAMETER     = (2)
	EFI_UNSUPPORTED           = (3)
	EFI_BAD_BUFFER_SIZE       = (4)
	EFI_BUFFER_TOO_SMALL      = (5)
	EFI_NOT_READY             = (6)
	EFI_DEVICE_ERROR          = (7)
	EFI_WRITE_PROTECTED       = (8)
	EFI_OUT_OF_RESOURCES      = (9)
	EFI_VOLUME_CORRUPTED      = (10)
	EFI_VOLUME_FULL           = (11)
	EFI_NO_MEDIA              = (12)
	EFI_MEDIA_CHANGED         = (13)
	EFI_NOT_FOUND             = (14)
	EFI_ACCESS_DENIED         = (15)
	EFI_NO_RESPONSE           = (16)
	EFI_NO_MAPPING            = (17)
	EFI_TIMEOUT               = (18)
	EFI_NOT_STARTED           = (19)
	EFI_ALREADY_STARTED       = (20)
	EFI_ABORTED               = (21)
	EFI_ICMP_ERROR            = (22)
	EFI_TFTP_ERROR            = (23)
	EFI_PROTOCOL_ERROR        = (24)
	EFI_INCOMPATIBLE_VERSION  = (25)
	EFI_SECURITY_VIOLATION    = (26)
	EFI_CRC_ERROR             = (27)
	EFI_END_OF_MEDIA          = (28)
	EFI_END_OF_FILE           = (31)
	EFI_INVALID_LANGUAGE      = (32)
	EFI_COMPROMISED_DATA      = (33)
	EFI_WARN_UNKOWN_GLYPH     = (1)
	EFI_WARN_UNKNOWN_GLYPH    = (1)
	EFI_WARN_DELETE_FAILURE   = (2)
	EFI_WARN_WRITE_FAILURE    = (3)
	EFI_WARN_BUFFER_TOO_SMALL = (4)
)

// EFIVariable is a variable type.
// In our can't-make-this-shit-up category, GUIDs have a name and a variable.
// Name because nobody likes to just use GUIDs.
// GUID because names might collide.
// Could they have done a path, back in the day? Well, sure, but
// GUIDs are so wonderful!
// We store the name as the form NAME:GUID, where name is the string and GUID
// is the string form of the GUID.
type EFIVariable struct {
	N    string
	Attr uintptr
	Data []byte
}

var (
	EFIVariables = map[string]*EFIVariable{}
	errors       = []string{
		0:  "EFI_SUCCESS",
		1:  "EFI_LOAD_ERROR",
		2:  "EFI_INVALID_PARAMETER",
		3:  "EFI_UNSUPPORTED",
		4:  "EFI_BAD_BUFFER_SIZE",
		5:  "EFI_BUFFER_TOO_SMALL",
		6:  "EFI_NOT_READY",
		7:  "EFI_DEVICE_ERROR",
		8:  "EFI_WRITE_PROTECTED",
		9:  "EFI_OUT_OF_RESOURCES",
		10: "EFI_VOLUME_CORRUPTED",
		11: "EFI_VOLUME_FULL",
		12: "EFI_NO_MEDIA",
		13: "EFI_MEDIA_CHANGED",
		14: "EFI_NOT_FOUND",
		15: "EFI_ACCESS_DENIED",
		16: "EFI_NO_RESPONSE",
		17: "EFI_NO_MAPPING",
		18: "EFI_TIMEOUT",
		19: "EFI_NOT_STARTED",
		20: "EFI_ALREADY_STARTED",
		21: "EFI_ABORTED",
		22: "EFI_ICMP_ERROR",
		23: "EFI_TFTP_ERROR",
		24: "EFI_PROTOCOL_ERROR",
		25: "EFI_INCOMPATIBLE_VERSION",
		26: "EFI_SECURITY_VIOLATION",
		27: "EFI_CRC_ERROR",
		28: "EFI_END_OF_MEDIA",
		31: "EFI_END_OF_FILE",
		32: "EFI_INVALID_LANGUAGE",
		33: "EFI_COMPROMISED_DATA",
	}

	warnings = []string{
		1: "EFI_WARN_UNKOWN_GLYPH",
		// it's there twice in efi.h. 1: EFI_WARN_UNKNOWN_GLYPH,
		2: "EFI_WARN_DELETE_FAILURE",
		3: "EFI_WARN_WRITE_FAILURE",
		4: "EFI_WARN_BUFFER_TOO_SMALL",
	}
)

// EFIError implements error
type EFIError struct {
	Err error
	Val uintptr
}

func (e EFIError) Error() string {
	s := strconv.Itoa(int(e.Val))
	if 0 <= int(e.Val) && int(e.Val) < len(errors) {
		s = errors[e.Val]
	}
	return "EFIERR " + e.Err.Error() + s
}

func (e EFIError) Is(target error) bool {
	return target != nil
}

// ReadVariable reads a UEFI variable
func ReadVariable(n string, g guid.GUID) (*EFIVariable, error) {
	p := fmt.Sprintf("%s:%s", n, g)
	v, ok := EFIVariables[p]
	if !ok {
		return nil, fmt.Errorf("%s is not set", p)
	}
	return v, nil
}

// EfiErrUint returns a uintptr for an EFI Error
func EFIErr(e EFIError) uintptr {
	return uintptr(1<<63) | uintptr(e.Val)
}

// oh, barf.
// Did someone just not get the memo about using more than a single bit and
// in particular not using 1 to mean something. Guess so.
const (
	EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL  = 0x00000001
	EFI_OPEN_PROTOCOL_GET_PROTOCOL        = 0x00000002
	EFI_OPEN_PROTOCOL_TEST_PROTOCOL       = 0x00000004
	EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER = 0x00000008
	EFI_OPEN_PROTOCOL_BY_DRIVER           = 0x00000010
	EFI_OPEN_PROTOCOL_EXCLUSIVE           = 0x00000020
)

// from u-boot:
// UEFI has a poor man's OO model where one "object" can be polymorphic and have
// multiple different protocols (classes) attached to it.
// The hits just keep coming.
// But we have a secret weapon.
// We are presenting the program with abstract devices, such as a ConIn or BlockIO.
// The "polymorphism" is handled in the RunDXERun or in Linux. Given that, the mapping
// of a handle to multiple protocols doesn't matter. Further, at ProtocolOpen time,
// it will suffice to know the Protocol GUID, since the mapping of handle->Protocol GUID is 1:1:,
// and BOTH the handle and GUID are presented each time.
// SO:
// Handles pointers will point to themselves, so deref is safe; the value can be ignored
// since only the Protocol GUID matters, as this polymorphism nonsense can be handled
// in other ways.
// Having a real kernel, instead of UEFI runtime, has benefits.
