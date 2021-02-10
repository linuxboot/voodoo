#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <efi.h>
#include <efilib.h>

// Application entrypoint (must be set to 'efi_main' for gnu-efi crt0 compatibility)
int main(int argc, char *argv[])
{
	FILE *f = popen("gofmt", "w");
	if (f == NULL) {
		perror("open");
		exit(1);
	}
	if (argc > 1)
		f = stdout;
	fprintf(f, "package table\n\nconst (\n");
	fprintf(f, "LIRevision = %#lx\n", offsetof(EFI_LOADED_IMAGE, Revision));
	fprintf(f, "LIParentHandle = %#lx\n", offsetof(EFI_LOADED_IMAGE, ParentHandle));
	fprintf(f, "LISystemTable = %#lx\n", offsetof(EFI_LOADED_IMAGE, SystemTable));
	fprintf(f, "LIDeviceHandle = %#lx\n", offsetof(EFI_LOADED_IMAGE, DeviceHandle));
	fprintf(f, "LIFilePath = %#lx\n", offsetof(EFI_LOADED_IMAGE, FilePath));
	fprintf(f, "LIReserved = %#lx\n", offsetof(EFI_LOADED_IMAGE, Reserved));
	fprintf(f, "LILoadOptionsSize = %#lx\n", offsetof(EFI_LOADED_IMAGE, LoadOptionsSize));
	fprintf(f, "LILoadOptions = %#lx\n", offsetof(EFI_LOADED_IMAGE, LoadOptions));
	fprintf(f, "LIImageBase = %#lx\n", offsetof(EFI_LOADED_IMAGE, ImageBase));
	fprintf(f, "LIImageSize = %#lx\n", offsetof(EFI_LOADED_IMAGE, ImageSize));
	fprintf(f, "LIImageCodeType = %#lx\n", offsetof(EFI_LOADED_IMAGE, ImageCodeType));
	fprintf(f, "LIImageDataType = %#lx\n", offsetof(EFI_LOADED_IMAGE, ImageDataType));
	fprintf(f, "LIUnload = %#lx\n", offsetof(EFI_LOADED_IMAGE, Unload));
	fprintf(f, ")\n");

	fprintf(f, "var LoadedImageTableNames = map[uint64]*val{\n");
	fprintf(f, "LIRevision: &val{N: \"Revision\"},\n");
	fprintf(f, "LIParentHandle: &val{N: \"ParentHandle\",},\n");
	fprintf(f, "LISystemTable: &val{N: \"SystemTable\",},\n");
	fprintf(f, "LIDeviceHandle: &val{N: \"DeviceHandle\",},\n");
	fprintf(f, "LIFilePath: &val{N: \"FilePath\",},\n");
	fprintf(f, "LIReserved: &val{N: \"Reserved\",},\n");
	fprintf(f, "LILoadOptionsSize: &val{N: \"LoadOptionsSize\",},\n");
	fprintf(f, "LILoadOptions: &val{N: \"LoadOptions\",},\n");
	fprintf(f, "LIImageBase: &val{N: \"ImageBase\",},\n");
	fprintf(f, "LIImageSize: &val{N: \"ImageSize\",},\n");
	fprintf(f, "LIImageCodeType: &val{N: \"ImageCodeType\",},\n");
	fprintf(f, "LIImageDataType: &val{N: \"ImageDataType\",},\n");
	fprintf(f, "LIUnload: &val{N: \"Unload\",},\n");
	fprintf(f, "}\n");

	pclose(f);
}
