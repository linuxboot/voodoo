#define _POSIX_C_SOURCE 201212L
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main() {
#define EFI_LOADED_IMAGE_PROTOCOL_GUID					\
	{								\
		0x5B1B31A1, 0x9562, 0x11d2, {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B} \
	}


//
// EFI_SYSTEM_TABLE & EFI_IMAGE_UNLOAD are defined in EfiApi.h
//
#define EFI_LOADED_IMAGE_INFORMATION_REVISION 0x1000
#define VOID uint8_t
	typedef uint64_t UINT64;
	typedef uint32_t UINT32;
	typedef void *EFI_HANDLE;
	typedef void *EFI_SYSTEM_TABLE;
	typedef void *EFI_DEVICE_PATH_PROTOCOL;
	typedef void *EFI_IMAGE_UNLOAD;
	typedef enum {
		EfiReservedMemoryType,
		EfiLoaderCode,
		EfiLoaderData,
		EfiBootServicesCode,
		EfiBootServicesData,
		EfiRuntimeServicesCode,
		EfiRuntimeServicesData,
		EfiConventionalMemory,
		EfiUnusableMemory,
		EfiACPIReclaimMemory,
		EfiACPIMemoryNVS,
		EfiMemoryMappedIO,
		EfiMemoryMappedIOPortSpace,
		EfiPalCode,
		EfiMaxMemoryType
	} EFI_MEMORY_TYPE;
	typedef uint32_t UINT32;
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

	} EFI_LOADED_IMAGE_PROTOCOL;
	printf("Revision %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, Revision), offsetof(EFI_LOADED_IMAGE_PROTOCOL, Revision));
	printf("ParentHandle %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, ParentHandle), offsetof(EFI_LOADED_IMAGE_PROTOCOL, ParentHandle));
	printf("SystemTable %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, SystemTable), offsetof(EFI_LOADED_IMAGE_PROTOCOL, SystemTable));
	printf("DeviceHandle %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, DeviceHandle), offsetof(EFI_LOADED_IMAGE_PROTOCOL, DeviceHandle));
	printf("FilePath %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, FilePath), offsetof(EFI_LOADED_IMAGE_PROTOCOL, FilePath));
	printf("Reserved %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, Reserved), offsetof(EFI_LOADED_IMAGE_PROTOCOL, Reserved));
	printf("LoadOptionsSize %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, LoadOptionsSize), offsetof(EFI_LOADED_IMAGE_PROTOCOL, LoadOptionsSize));
	printf("LoadOptions %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, LoadOptions), offsetof(EFI_LOADED_IMAGE_PROTOCOL, LoadOptions));
	printf("ImageBase %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, ImageBase), offsetof(EFI_LOADED_IMAGE_PROTOCOL, ImageBase));
	printf("ImageSize %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, ImageSize), offsetof(EFI_LOADED_IMAGE_PROTOCOL, ImageSize));
	printf("ImageCodeType %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, ImageCodeType), offsetof(EFI_LOADED_IMAGE_PROTOCOL, ImageCodeType));
	printf("ImageDataType %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, ImageDataType), offsetof(EFI_LOADED_IMAGE_PROTOCOL, ImageDataType));
	printf("Unload %#lx %ld\n", offsetof(EFI_LOADED_IMAGE_PROTOCOL, Unload), offsetof(EFI_LOADED_IMAGE_PROTOCOL, Unload));


}
