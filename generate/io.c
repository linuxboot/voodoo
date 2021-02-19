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
#define t(x) fprintf(f, "STOut" #x " = %#lx\n", offsetof(SIMPLE_TEXT_OUTPUT_INTERFACE, x));
	t(Reset)
	t(OutputString)
	t(TestString)
	t(QueryMode)
	t(SetMode)
	t(SetAttribute)
	t(ClearScreen)
	t(SetCursorPosition)
	t(EnableCursor)
	t(Mode)
	fprintf(f, ")\n");

	fprintf(f, "var SimpleTextOutServicesNames = map[uint64]*val{\n");
#define tab(x) fprintf(f, "STOut" #x ": &val{N: \"" #x "\"},\n");
	tab(Reset)
	tab(OutputString)
	tab(TestString)
	tab(QueryMode)
	tab(SetMode)
	tab(SetAttribute)
	tab(ClearScreen)
	tab(SetCursorPosition)
	tab(EnableCursor)
	tab(Mode)
	fprintf(f, "}\n");

	#undef t
	#undef tab
	// the naming is *so* consistent
	#define t(x) fprintf(f, "STIn" #x " = %#lx\n", offsetof(EFI_SIMPLE_TEXT_IN_PROTOCOL, x));
	fprintf(f, "const (\n");
	t(Reset);
	t(ReadKeyStroke);
	t(WaitForKey);
	fprintf(f, ")\n");
#undef t
#define t(x) fprintf(f, "STIn" #x ": &val{N: \"" #x "\"},\n");
	fprintf(f, "var SimpleTextInServicesNames = map[uint64]*val{\n");
	t(Reset);
	t(ReadKeyStroke);
	t(WaitForKey);
	fprintf(f, "}\n");
	
	pclose(f);
}
