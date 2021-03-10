#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <efi.h>
#include <efilib.h>

// 1D85CD7F-F43D-11D2-9A0C-0090273FC14D
// UEFI picked the wrong character coding in the age of utf-8

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
#define t(x) fprintf(f, "Coll" #x " = %#lx\n", offsetof(EFI_UNICODE_COLLATION_PROTOCOL, x));
	// general
	t(StriColl);
	t(MetaiMatch);
	t(StrLwr);
	t(StrUpr);
	// for supporting fat volumes
	t(FatToStr);
	t(StrToFat);
	t(SupportedLanguages);
	fprintf(f, ")\n");

	fprintf(f, "var CollateServicesNames = map[uint64]*val{\n");

#undef t
#define t(x) fprintf(f, "Coll" #x ": &val{N: \"" #x "\"},\n");
	// general
	t(StriColl);
	t(MetaiMatch);
	t(StrLwr);
	t(StrUpr);
	// for supporting fat volumes
	t(FatToStr);
	t(StrToFat);
	t(SupportedLanguages);
	fprintf(f, "}\n");
	pclose(f);
}
