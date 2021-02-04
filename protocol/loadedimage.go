package protocol

/* from the belly of the EFI best.
#define EFI_LOADED_IMAGE_PROTOCOL_GUID \
  { \
    0x5B1B31A1, 0x9562, 0x11d2, {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B} \
  }

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

// NewLoadedImage returns a filled-in LoadedImage struct. As to correctness, we have no idea.
func NewLoadedImage() (*LoadedImage, error) {
	return &LoadedImage{
		Revision: LoadedImageRevision,
	}, nil
}
