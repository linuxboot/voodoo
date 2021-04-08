all: collate io runtime loadedimage systemtable getsig protocol
GNUEFI_DIR?=/home/rminnich/foofi/uefi-simple/gnu-efi/
GNUEFI_ARCH?=x86_64
CFLAGS         += -fno-stack-protector -Wshadow -Wall -Wunused -Werror-implicit-function-declaration
CFLAGS         += -I$(GNUEFI_DIR)/inc -I$(GNUEFI_DIR)/inc/$(GNUEFI_ARCH) -I$(GNUEFI_DIR)/inc/protocol
CFLAGS         += -DCONFIG_$(GNUEFI_ARCH) -D__MAKEWITH_GNUEFI -DGNU_EFI_USE_MS_ABI

blockio: blockio.c
	cc $(CFLAGS) -o $@ $<

collate: collate.c
	cc $(CFLAGS) -o $@ $<

io: io.c
	cc $(CFLAGS) -o $@ $<

runtime: runtime.c
	cc $(CFLAGS) -o $@ $<

loadedimage: loadedimage.c
	cc $(CFLAGS) -o $@ $<

systemtable: systemtable.c
	cc $(CFLAGS) -o $@ $<

getsig: getsig.c
	cc -o getsig getsig.c

protocol: protocol.c
	cc -o protocol protocol.c

