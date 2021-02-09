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
	fprintf(f,
"		package table\n"
"\n"
"var SystemSig = []byte{0x54, 0x53, 0x59, 0x53, 0x20, 0x49, 0x42, 0x49}\n"
"\n"
"//#define EFI_SYSTEM_TABLE_REVISION      (EFI_SPECIFICATION_MAJOR_REVISION<<16) | (EFI_SPECIFICATION_MINOR_REVISION)\n"
"\n"
"type SystemTable struct {\n"
"	TableHeader\n"
"\n"
"	Vendor           uint16\n"
"	Revision         uint32\n"
"	FirmwareVendor   uintptr\n"
"	FirmwareRevision uint32\n"
"\n"
"	ConsoleInHandle uintptr\n"
"	ConIn           uintptr\n"
"\n"
"	ConsoleOutHandle uintptr\n"
"	ConOut           uintptr\n"
"\n"
"	StandardErrorHandle uintptr\n"
"	StdErr              uintptr\n"
"\n"
"	RuntimeServices uintptr\n"
"	BootServices    uintptr\n"
"\n"
"	NumberOfTableEntries uintptr\n"
"	ConfigurationTable   uintptr\n"
"}\nconst (\n"
);

	fprintf(f, "Hdr = %#lx\n", offsetof(EFI_SYSTEM_TABLE, Hdr));
	fprintf(f, "FirmwareVendor = %#lx\n", offsetof(EFI_SYSTEM_TABLE, FirmwareVendor));
	fprintf(f, "FirmwareRevision = %#lx\n", offsetof(EFI_SYSTEM_TABLE, FirmwareRevision));
	fprintf(f, "ConsoleInHandle = %#lx\n", offsetof(EFI_SYSTEM_TABLE, ConsoleInHandle));
	fprintf(f, "ConIn = %#lx\n", offsetof(EFI_SYSTEM_TABLE, ConIn));
	fprintf(f, "ConsoleOutHandle = %#lx\n", offsetof(EFI_SYSTEM_TABLE, ConsoleOutHandle));
	fprintf(f, "ConOut = %#lx\n", offsetof(EFI_SYSTEM_TABLE, ConOut));
	fprintf(f, "StandardErrorHandle = %#lx\n", offsetof(EFI_SYSTEM_TABLE, StandardErrorHandle));
	fprintf(f, "StdErr = %#lx\n", offsetof(EFI_SYSTEM_TABLE, StdErr));
	fprintf(f, "RuntimeServices = %#lx\n", offsetof(EFI_SYSTEM_TABLE, RuntimeServices));
	fprintf(f, "BootServices = %#lx\n", offsetof(EFI_SYSTEM_TABLE, BootServices));
	fprintf(f, "NumberOfTableEntries = %#lx\n", offsetof(EFI_SYSTEM_TABLE, NumberOfTableEntries));
	fprintf(f, "ConfigurationTable  = %#lx\n", offsetof(EFI_SYSTEM_TABLE, ConfigurationTable ));
	fprintf(f, ")\n");
	fprintf(f, "type val struct {\nN string\nVal uint64\n}\n");
	fprintf(f, "// SystemTableNames provide names and values for system table entries.\n");
	fprintf(f, "var SystemTableNames = map[uint64]*val{\n");
	fprintf(f, "Hdr: &val{N: \"Hdr\",},\n");
	fprintf(f, "FirmwareVendor: &val{N:\"FirmwareVendor\",},\n");
	fprintf(f, "FirmwareRevision: &val{N: \"FirmwareRevision\",},\n");
	fprintf(f, "ConsoleInHandle: &val{N: \"ConsoleInHandle\",},\n");
	fprintf(f, "ConIn: &val{N: \"ConIn\",},\n");
	fprintf(f, "ConsoleOutHandle: &val{N: \"ConsoleOutHandle\",},\n");
	fprintf(f, "ConOut: &val{N: \"ConOut\",},\n");
	fprintf(f, "StandardErrorHandle: &val{N: \"StandardErrorHandle\",},\n");
	fprintf(f, "StdErr: &val{N: \"StdErr\",},\n");
	fprintf(f, "RuntimeServices: &val{N: \"RuntimeServices\",},\n");
	fprintf(f, "BootServices: &val{N: \"BootServices\",},\n");
	fprintf(f, "NumberOfTableEntries: &val{N: \"NumberOfTableEntries\",},\n");
	fprintf(f, "ConfigurationTable: &val{N: \"ConfigurationTable\",},\n");
	fprintf(f, "}\n");
	pclose(f);
}
