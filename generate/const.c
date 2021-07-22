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
	fprintf(f, "EfiHandleSize = %ld\n", sizeof (EFI_HANDLE));
	fprintf(f, ")");
	pclose(f);
}
