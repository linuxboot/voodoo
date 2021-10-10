#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <efi.h>
#include <efilib.h>

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
	fprintf(f, "RTHdr = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, Hdr));
	fprintf(f, "RTGetTime = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, GetTime));
	fprintf(f, "RTSetTime = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, SetTime));
	fprintf(f, "RTGetWakeupTime = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, GetWakeupTime));
	fprintf(f, "RTSetWakeupTime = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, SetWakeupTime));
	fprintf(f, "RTSetVirtualAddressMap = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, SetVirtualAddressMap));
	fprintf(f, "RTConvertPointer = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, ConvertPointer));
	fprintf(f, "RTGetVariable = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, GetVariable));
	fprintf(f, "RTGetNextVariableName = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, GetNextVariableName));
	fprintf(f, "RTSetVariable = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, SetVariable));
	fprintf(f, "RTGetNextHighMonotonicCount = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, GetNextHighMonotonicCount));
	fprintf(f, "RTResetSystem = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, ResetSystem));
	fprintf(f, "RTUpdateCapsule = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, UpdateCapsule));
	fprintf(f, "RTQueryCapsuleCapabilities = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, QueryCapsuleCapabilities));
	fprintf(f, "RTQueryVariableInfo = %#lx\n", offsetof(EFI_RUNTIME_SERVICES, QueryVariableInfo));

	fprintf(f, ")\n");

	fprintf(f, "var RuntimeServicesNames = map[uint64]*val{\n");
	fprintf(f, "RTHdr: &val{N: \"Hdr\"},\n");
	fprintf(f, "RTGetTime: &val{N: \"GetTime\"},\n");
	fprintf(f, "RTSetTime: &val{N: \"SetTime\"},\n");
	fprintf(f, "RTGetWakeupTime: &val{N: \"GetWakeupTime\"},\n");
	fprintf(f, "RTSetWakeupTime: &val{N: \"SetWakeupTime\"},\n");
	fprintf(f, "RTSetVirtualAddressMap: &val{N: \"SetVirtualAddressMap\"},\n");
	fprintf(f, "RTConvertPointer: &val{N: \"ConvertPointer\"},\n");
	fprintf(f, "RTGetVariable: &val{N: \"GetVariable\"},\n");
	fprintf(f, "RTGetNextVariableName: &val{N: \"GetNextVariableName\"},\n");
	fprintf(f, "RTSetVariable: &val{N: \"SetVariable\"},\n");
	fprintf(f, "RTGetNextHighMonotonicCount: &val{N: \"GetNextHighMonotonicCount\"},\n");
	fprintf(f, "RTResetSystem: &val{N: \"ResetSystem\"},\n");
	fprintf(f, "RTUpdateCapsule: &val{N: \"UpdateCapsule\"},\n");
	fprintf(f, "RTQueryCapsuleCapabilities: &val{N: \"QueryCapsuleCapabilities\"},\n");
	fprintf(f, "RTQueryVariableInfo: &val{N: \"QueryVariableInfo\"},\n");
	fprintf(f, "}\n");

	fprintf(f, "type EfiTime struct {\n"
		"	Year uint16\n"
		"	Month uint8\n"
		"	Day uint8\n"
		"	Hour uint8\n"
		"	Minute uint8\n"
		"	Second uint8\n"
		"	_ uint8\n"
		"	Nanosecond uint32\n"
		"	Timezone int16\n"
		"	Daylight uint8\n"
		"		_ uint8\n"
		"}\n");
	fprintf(f, "type EfiTimeCap struct {\n"
		"	Resolution uint32\n"
		"	Accuracy uint32\n"
		"	SetsToZero uint8\n"
		"}\n");
	pclose(f);
}
