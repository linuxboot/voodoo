
unsigned short b[0x80000000];
int main(int argc, char *argv[])
{
	for(int i = 0; i < 0x80000000; i += 4096)
		b[i] = 0x0f0b;
	while (1);
}
