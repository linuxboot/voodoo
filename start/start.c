#include <sys/mman.h>
#include <stdlib.h>

unsigned short b[0x1000];
int main(int argc, char *argv[])
{
	if (0)
	for(int i = 0; i < 0x80000000; i += 4096)
		b[i] = 0x0f0b;
			if (mmap((void *)0x500000, 0x80000000, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE, -1, 0) < 0)
				exit(2);
	while (1);
}
