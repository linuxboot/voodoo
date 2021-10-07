/*
 * UEFI:SIMPLE - UEFI development made easy
 * Copyright © 2014-2018 Pete Batard <pete@akeo.ie> - Public Domain
 * See COPYING for the full licensing terms.
 */
#include <efi.h>
#include <efilib.h>

static inline void cpuid(int code, uint32_t *aa, uint32_t *da) {
// uint32_t a, d;
	//asm volatile("cpuid":"=a"(a),"=d"(d):"a"(code):"ecx","ebx");
	asm volatile("cpuid"::"a"(code):"edx", "ecx","ebx");
}
static inline void cpuid_fucked(int code, uint32_t where[4]) {
	//uint32_t a, b, c, d;
//  asm volatile("cpuid":"=a"(a),"=b"((b)),
	//"=c"((c)),"=d"((d)):"a"(code));
	//where[0] = a;
	//where[1] = b;
	//where[2] = c;
	//where[3] = d;
}
static __inline int
grub_cpu_is_cpuid_supported (void)
{
	uint64_t id_supported;

	__asm__ ("pushfq\n\t"
		 "popq %%rax             /* Get EFLAGS into EAX */\n\t"
		 "movq %%rax, %%rcx      /* Save original flags in ECX */\n\t"
		 "xorq $0x200000, %%rax  /* Flip ID bit in EFLAGS */\n\t"
		 "pushq %%rax            /* Store modified EFLAGS on stack */\n\t"
		 "popfq                  /* Replace current EFLAGS */\n\t"
		 "pushfq                 /* Read back the EFLAGS */\n\t"
		 "popq %%rax             /* Get EFLAGS into EAX */\n\t"
		 "xorq %%rcx, %%rax      /* Check if flag could be modified */\n\t"
		 : "=a" (id_supported)
		 : /* No inputs.  */
		 : /* Clobbered:  */ "%rcx");

	return id_supported != 0;
}
// Application entrypoint (must be set to 'efi_main' for gnu-efi crt0 compatibility)
EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
	//uint32_t w[4] = {};
	//int op = 0;
	EFI_STATUS status;
	//UINTN Event;
	// global EFI_BOOT_SERVICES *BS = SystemTable->BootServices;
	EFI_LOADED_IMAGE_PROTOCOL *elip;
#if defined(_GNU_EFI)
	InitializeLib(ImageHandle, SystemTable);
#endif

	/*
	 * In addition to the standard %-based flags, Print() supports the following:
	 *   %N       Set output attribute to normal
	 *   %H       Set output attribute to highlight
	 *   %E       Set output attribute to error
	 *   %B       Set output attribute to blue color
	 *   %V       Set output attribute to green color
	 *   %r       Human readable version of a status code
	 */
	Print(L"\n%H*** UEFI:SIMPLE ***%N\n\n");
	status = uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID *)&elip);
	if ((uint64_t)elip == 0xFF000000ULL)
		Print(L"pointer to loaded image protocol value looks GOOD\n");
	else
		Print(L"pointer to loaded image protocol value looks BAD, please fix\n");

	Print(L"HandleProtocol returns %r, guid %g, elip %x\n", status, &gEfiLoadedImageProtocolGuid, elip);

	Print(L"%Evia return? \n");
	return EFI_SUCCESS;
}

