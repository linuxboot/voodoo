#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <efi.h>
#include <efilib.h>

// 1D85CD7F-F43D-11D2-9A0C-0090273FC14D
// UEFI picked the wrong character coding in the age of utf-8
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
	FILE *f = popen("gofmt", "w");
	if (f == NULL) {
		perror("open");
		exit(1);
	}
	if (argc > 1)
		f = stdout;

	fprintf(f, "package table\n");
	fprintf(f, "\nconst BlockioGUID = \"1D85CD7F-F43D-11D2-9A0C-0090273FC14D\"\n");
	fprintf(f, "\nconst (\n");
#define t(x) fprintf(f, "Blockio" #x " = %#lx\n", offsetof(EFI_BLOCK_IO_PROTOCOL, x));
		t(Revision);
		t(Media);
		t(Reset);
		t(ReadBlocks);
		t(WriteBlocks);
		t(FlushBlocks);
	fprintf(f, ")\n");

	fprintf(f, "var BlockioServiceNames = map[uint64]*val{\n");

#undef t
#define t(x) fprintf(f, "Coll" #x ": &val{N: \"" #x "\"},\n");
		t(Revision);
		t(Media);
		t(Reset);
		t(ReadBlocks);
		t(WriteBlocks);
		t(FlushBlocks);
	fprintf(f, "}\n");
	pclose(f);
}
