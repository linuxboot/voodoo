package protocol

import (
	"bytes"
	"encoding/binary"
)

/* from the belly of the EFI best.
#define EFI_LOADED_IMAGE_PROTOCOL_GUID \
  { \
    0x5B1B31A1, 0x9562, 0x11d2, {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B} \
  }
2021/02/04 13:31:45 HandleProtocol: GUID 5B1B31A1-9562-11D2-8E3F-00A0C969723B

//
// EFI_SYSTEM_TABLE & EFI_IMAGE_UNLOAD are defined in EfiApi.h
//
#define EFI_LOADED_IMAGE_INFORMATION_REVISION 0x1000

typedef struct {
  UINT32                    Revision;
  EFI_HANDLE                ParentHandle;
  EFI_SYSTEM_TABLE          *SystemTable;

  //
  // Source location of image
  //
  EFI_HANDLE                DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL  *FilePath;
  VOID                      *Reserved;

  //
  // Images load options
  //
  UINT32                    LoadOptionsSize;
  VOID                      *LoadOptions;

  //
  // Location of where image was loaded
  //
  VOID                      *ImageBase;
  UINT64                    ImageSize;
  EFI_MEMORY_TYPE           ImageCodeType;
  EFI_MEMORY_TYPE           ImageDataType;

  //
  // If the driver image supports a dynamic unload request
  //
  EFI_IMAGE_UNLOAD          Unload;

} EFI_LOADED_IMAGE_PROTOCOL
*/

// LoadedImage is for the Loaded Image Protocol.
type LoadedImage struct {
	Revision uint32
	Parent   Handle
	System   Table

	//
	// Source location of image
	//
	Device   Handle
	FilePath uintptr
	_        uintptr

	//
	// Images load options
	//
	LoadOptionsSize uint32
	LoadOptions     uintptr

	//
	// Location of where image was loaded
	//
	ImageBase     uintptr
	ImageSize     uint64
	ImageCodeType MemoryType
	ImageDataType MemoryType

	//
	// If the driver image supports a dynamic unload request
	//
	/*EFI_IMAGE_UNLOAD*/
	Unload uintptr
}

var LoadedImageProtocol = "5B1B31A1-9562-11D2-8E3F-00A0C969723B"

var _ TableMarshaler = LoadedImage{}

func (i LoadedImage) Marshal() ([]byte, error) {
	var (
		w = &bytes.Buffer{}
		f = func(i ...interface{}) ([]byte, error) {
			for _, v := range i {
				if err := binary.Write(w, binary.LittleEndian, v); err != nil {
					return nil, err
				}
			}
			return w.Bytes(), nil
		}
	)
	return f(i.Revision, uint64(i.Parent), uint64(i.System), uint64(i.Device), uint64(i.FilePath), uint64(0), uint64(i.LoadOptions), uint64(i.ImageBase), uint64(i.ImageSize), uint64(i.ImageCodeType), uint64(i.ImageDataType), uint64(i.Unload))
}

// NewLoadedImage returns a filled-in LoadedImage struct. As to correctness, we have no idea.
// General rule: never leave anything with the zero value. It makes debugging much harder.
// Unless there are stupid UEFI reasons to make it zero, i.e. they have some default "type"
// and zero is a valid value. note: a valid value of zero is always a mistake. See Unix file open.
func NewLoadedImage() (*LoadedImage, error) {
	return &LoadedImage{
		Revision: LoadedImageRevision,
		// Parent damn. zero valie.
		// System damn.
		Device: 0x1cafe00000000,
		// FilePath damn.
		// LoadOptionsSize damn.
		// LoadOptions   damn.
		ImageBase: 0x200000,
		ImageSize: 0x400000,
		// ImageCodeType damn
		// ImageDataType damn.
		/*EFI_IMAGE_UNLOAD*/
		// Unload damn.
	}, nil
}
