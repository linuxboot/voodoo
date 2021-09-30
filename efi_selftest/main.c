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
	uint32_t w[4] = {};
	int op = 0;
	UINTN Event;
	
#if 0
	{
	int cc = *(int *)0xbbbbbb9f;
	    if (cc) 
            	EFIDebugVariable ();
	}
#endif
#if defined(_GNU_EFI)
	InitializeLib(ImageHandle, SystemTable);
#endif
#if 0
	{
	    int cc = *(int *)0xbbbbbba0;
	    if (cc) 
            	EFIDebugVariable ();
	}
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
	//cpuid(op, w);
	//cpuid(op, &w[0], &w[1]);
	uint32_t a, b, c, d;
	op = 0;
  	asm volatile("cpuid":"=a"(a):"a"(op):"edx", "ecx","ebx");
	Print(L"CPUID HI %d %x %x %x %x", op, a, w[1], w[2], w[3]);
	op = 0;
  	asm volatile("cpuid":"=a"(a), "=b"(b), "=c"(c), "=d"(d):"a"(op):);
	Print(L"CPUID HI %d %x %x %x %x", op, a, b, c, d);
	op = 1;
  	asm volatile("cpuid":"=a"(a), "=b"(b), "=c"(c), "=d"(d):"a"(op):);
	Print(L"CPUID HI %d %x %x %x %x", op, a, b, c, d);
	Print (L"(d & (1 << 4)) != 0 %d\n", (d & (1 << 4)) != 0);
	op = 0;
  	asm volatile("cpuid":"=a"(w[0]):"a"(op):"edx", "ecx","ebx");
	Print(L"CPUID HI %d %x %x %x %x", op, w[0], w[1], w[2], w[3]);
	op = 1;
  	asm volatile("cpuid":"=a"(w[0]):"a"(op):"edx", "ecx","ebx");
	Print(L"CPUID HI %d %x %x %x %x", op, w[0], w[1], w[2], w[3]);

	Print(L"%EPress any key to exit.%N\n");
	Print(L"let's see a 5 %d\n", 5);
	Print(L"call conin\n");
	SystemTable->ConIn->Reset(SystemTable->ConIn, FALSE);
	SystemTable->BootServices->WaitForEvent(1, &SystemTable->ConIn->WaitForKey, &Event);
	Print(L"%EGot the key, exiting\n");
	EFI_STATUS      Status;
	UINTN           NumberHandles = 8, Index;
	EFI_HANDLE      *Handles = (void *)0xdeadbeef;
	Print(L"Before call: NumberHandles %d handles %llx\n", NumberHandles, (uint64_t)Handles);
	Print(L"Before call: &NumberHandles %llx handles %llx\n", (uint64_t)&NumberHandles, (uint64_t)&Handles);
	if (1) {
		Status = LibLocateHandle (ByProtocol, &gEfiBlockIoProtocolGuid, NULL, &NumberHandles, &Handles);
#if 0
		int cc = *(int *)0xbbbbbbbd;
		if (cc) 
			EFIDebugVariable ();
#endif
		Print(L"Status is %llx\n", Status);
	}
	if (1) {
			if (EFI_ERROR(Status)) {
				Print(L"LibLocateProtocol: Handle not found\n");
				//return Status;
			}
	}
	if (1) {
			Print(L"NumberHandles %d handles %llx\n", NumberHandles, (uint64_t)Handles);
	}
	if (1) {

			for (Index=0; Index < NumberHandles; Index++) {
				Print(L"%d: %p", Index, Handles[Index]);
//        Status = uefi_call_wrapper(BS->HandleProtocol, 3, Handles[Index], ProtocolGuid, Interface);
				if (!EFI_ERROR(Status)) {
					break;
				}
			}

			if (Handles) {
				FreePool (Handles);
			}
	}
#if defined(_DEBUG)
	// If running in debug mode, use the EFI shut down call to close QEMU
	Print(L"%Evia QEMU? \n");
	SystemTable->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
#endif
        EFI_LOADED_IMAGE *loaded_image = NULL;
        EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL;
        EFI_STATUS status;

        status = uefi_call_wrapper(SystemTable->BootServices->HandleProtocol,
                                3,
				   ImageHandle,
                                &loaded_image_protocol,
                                (void **) &loaded_image);
        if (EFI_ERROR(status)) {
                Print(L"handleprotocol: %r\n", status);
        }

        Print(L"Image base        : %lx\n", loaded_image->ImageBase);
        Print(L"Image size        : %lx\n", loaded_image->ImageSize);
        Print(L"Image path        : %lx\n", loaded_image->FilePath);
	uint64_t *p64 = (uint64_t*)loaded_image->FilePath;
        Print(L"*Image path        : %lx\n", *p64);
        Print(L"Image file        : %s\n", DevicePathToStr(loaded_image->FilePath));

	Print(L"%Evia return? \n");
	return EFI_SUCCESS;
}

/* EFI_STATUS */
/* efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab) */
/* { */
/*         EFI_LOADED_IMAGE *loaded_image = NULL; */
/*         EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL; */
/*         EFI_STATUS status; */

/*         InitializeLib(image, systab); */
/*         status = uefi_call_wrapper(systab->BootServices->HandleProtocol, */
/*                                 3, */
/*                                 image,  */
/*                                 &loaded_image_protocol,  */
/*                                 (void **) &loaded_image); */
/*         if (EFI_ERROR(status)) { */
/*                 Print(L"handleprotocol: %r\n", status); */
/*         } */

/*         Print(L"Image base        : %lx\n", loaded_image->ImageBase); */
/*         Print(L"Image size        : %lx\n", loaded_image->ImageSize); */
/*         Print(L"Image file        : %s\n", DevicePathToStr(loaded_image->FilePath)); */
/*         return EFI_SUCCESS; */
/* } */
