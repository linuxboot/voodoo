#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <efi.h>
#include <efilib.h>

/*
typedef struct _EFI_BLOCK_IO_PROTOCOL EFI_BLOCK_IO_PROTOCOL;

///
/// This protocol provides control over block devices.
///
struct _EFI_BLOCK_IO_PROTOCOL {
  ///
  /// The revision to which the block IO interface adheres. All future
  /// revisions must be backwards compatible. If a future version is not
  /// back wards compatible, it is not the same GUID.
  ///
  UINT64 Revision;
  ///
  /// Pointer to the EFI_BLOCK_IO_MEDIA data for this device.
  ///
  EFI_BLOCK_IO_MEDIA *Media;

  EFI_BLOCK_RESET Reset;
  EFI_BLOCK_READ ReadBlocks;
  EFI_BLOCK_WRITE WriteBlocks;
  EFI_BLOCK_FLUSH FlushBlocks;

};

extern EFI_GUID gEfiBlockIoProtocolGuid;
*/

int main(int argc, char *argv[])
{
	EFI_GUID g = EFI_BLOCK_IO_PROTOCOL_GUID, *Guid = &g;
	FILE *f = popen("gofmt", "w");
	if (f == NULL) {
		perror("open");
		exit(1);
	}
	if (argc > 1)
		f = stdout;

	fprintf(f, "package table\n");
	fprintf(f, "const BlockIOGUID = \"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\"\n",
		Guid->Data1,
		Guid->Data2,
		Guid->Data3,
		Guid->Data4[0],
		Guid->Data4[1],
		Guid->Data4[2],
		Guid->Data4[3],
		Guid->Data4[4],
		Guid->Data4[5],
		Guid->Data4[6],
		Guid->Data4[7]
		);
	fprintf(f, "\nconst (\n");
#define t(x) fprintf(f, "BlockIO" #x " = %#lx\n", offsetof(EFI_BLOCK_IO_PROTOCOL, x));
		t(Revision);
		t(Media);
		t(Reset);
		t(ReadBlocks);
		t(WriteBlocks);
		t(FlushBlocks);
	fprintf(f, ")\n");

	fprintf(f, "var BlockIOServiceNames = map[uint64]*val{\n");

#undef t
#define t(x) fprintf(f, "BlockIO" #x ": &val{N: \"" #x "\"},\n");
		t(Revision);
		t(Media);
		t(Reset);
		t(ReadBlocks);
		t(WriteBlocks);
		t(FlushBlocks);
	fprintf(f, "}\n");
	pclose(f);
}
