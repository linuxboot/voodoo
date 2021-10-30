ARCH            ?= x64
# other choices: aa64, ia32, arm
# You can alter the subsystem according to your EFI binary target:
# 10 = EFI application
# 11 = EFI boot service driver
# 12 = EFI runtime driver
SUBSYSTEM       = 10

# Try to auto-detect the target ARCH
# fuck this. It's stupid.
#ifeq ($(shell uname -o),Msys)
#  IS_MINGW32    = $(findstring MINGW32,$(shell uname -s))
#  IS_MINGW64    = $(findstring MINGW64,$(shell uname -s))
#  ifeq ($(IS_MINGW32),MINGW32)
#    ARCH        = ia32
#  endif
#  ifeq ($(IS_MINGW64),MINGW64)
#    ARCH        = x64
#  endif
#else
#  ifeq ($(shell uname -m),x86_64)
#    ARCH        = x64
#  else ifeq ($(shell uname -m),arm)
#    ARCH        = arm
#    CROSS_COMPILE =
#  else ifeq ($(shell uname -m),aarch64)
#    ARCH        = aa64
#    CROSS_COMPILE =
#  else
#    ARCH        = ia32
#  endif
#endif

# Auto-detect the host arch for MinGW
ifeq ($(shell uname -m),x86_64)
  MINGW_HOST    = w64
else
  MINGW_HOST    = w32
endif

ifeq ($(ARCH),x64)
  GNUEFI_ARCH   = x86_64
  GCC_ARCH      = x86_64
  QEMU_ARCH     = x86_64
  FW_BASE       = OVMF
  CROSS_COMPILE = $(GCC_ARCH)-$(MINGW_HOST)-mingw32-
  EP_PREFIX     =
  CFLAGS        = -m64 -mno-red-zone
  LDFLAGS       = -Wl,-dll -Wl,--subsystem,$(SUBSYSTEM)
else ifeq ($(ARCH),ia32)
  GNUEFI_ARCH   = ia32
  GCC_ARCH      = i686
  QEMU_ARCH     = i386
  FW_BASE       = OVMF
  CROSS_COMPILE = $(GCC_ARCH)-$(MINGW_HOST)-mingw32-
  EP_PREFIX     = _
  CFLAGS        = -m32 -mno-red-zone
  LDFLAGS       = -Wl,-dll -Wl,--subsystem,$(SUBSYSTEM)
else ifeq ($(ARCH),arm)
  GNUEFI_ARCH   = arm
  GCC_ARCH      = arm
  QEMU_ARCH     = arm
  FW_BASE       = QEMU_EFI
  CROSS_COMPILE = $(GCC_ARCH)-linux-gnueabihf-
  EP_PREFIX     =
  CFLAGS        = -marm -fpic -fshort-wchar
  LDFLAGS       = -Wl,--no-wchar-size-warning -Wl,--defsym=EFI_SUBSYSTEM=$(SUBSYSTEM)
  CRT0_LIBS     = -lgnuefi
  QEMU_OPTS     = -M virt -cpu cortex-a15
else ifeq ($(ARCH),aa64)
  GNUEFI_ARCH   = aarch64
  GCC_ARCH      = aarch64
  QEMU_ARCH     = aarch64
  FW_BASE       = QEMU_EFI
  CROSS_COMPILE = $(GCC_ARCH)-linux-gnu-
  EP_PREFIX     =
  CFLAGS        = -fpic -fshort-wchar -march=armv8-a
  LDFLAGS       = -Wl,--no-wchar-size-warning -Wl,--defsym=EFI_SUBSYSTEM=$(SUBSYSTEM)
  LDFLAGS       += -Tgcc.ld -Wl,--gc-sections,-Map=$(APP).map $(LDFLAGS_EXTRA) -static
  CRT0_LIBS     = -lgnuefi
  QEMU_OPTS     = -M virt -cpu cortex-a57
endif
FW_ARCH         = $(shell echo $(ARCH) | tr a-z A-Z)
FW_ZIP          = $(FW_BASE)-$(FW_ARCH).zip
GNUEFI_DIR      = $(GNUEFIDIR)/gnu-efi
GNUEFI_LIBS     = lib

# If the compiler produces an elf binary, we need to fiddle with a PE crt0
ifneq ($(CRT0_LIBS),)
  CRT0_DIR      = $(GNUEFI_DIR)/$(GNUEFI_ARCH)/gnuefi
  LDFLAGS      += -L$(CRT0_DIR) -T $(GNUEFI_DIR)/gnuefi/elf_$(GNUEFI_ARCH)_efi.lds $(CRT0_DIR)/crt0-efi-$(GNUEFI_ARCH).o
  GNUEFI_LIBS  += gnuefi
endif

# SYSTEMROOT is only defined on Windows systems
ifneq ($(SYSTEMROOT),)
  QEMU          = "/c/Program Files/qemu/qemu-system-$(QEMU_ARCH)w.exe"
  # MinGW on Windows doesn't use (tuple)-ar but (tuple)-gcc-ar
  # so we remove the cross compiler tuple altogether
  CROSS_COMPILE =
else
  QEMU          = qemu-system-$(QEMU_ARCH) -nographic
endif

CC             := $(CROSS_COMPILE)gcc
OBJCOPY        := $(CROSS_COMPILE)objcopy
CFLAGS         += -fno-stack-protector -Wshadow -Wall -Wunused -Werror-implicit-function-declaration
CFLAGS         += -I$(GNUEFI_DIR)/inc -I$(GNUEFI_DIR)/inc/$(GNUEFI_ARCH) -I$(GNUEFI_DIR)/inc/protocol
CFLAGS         += -DCONFIG_$(GNUEFI_ARCH) -D__MAKEWITH_GNUEFI -DGNU_EFI_USE_MS_ABI
CFLAGS         += -DEFI_DEBUG
LDFLAGS        += -L$(GNUEFI_DIR)/$(GNUEFI_ARCH)/lib -e $(EP_PREFIX)efi_main
# don't be stupid and strip it. Why strip it? no idea.
# LDFLAGS        += -s -Wl,-Bsymbolic -nostdlib -shared
LDFLAGS        += -Wl,-Bsymbolic -nostdlib -shared
LIBS            = -lefi $(CRT0_LIBS)

ifeq (, $(shell which $(CC)))
  $(error The selected compiler ($(CC)) was not found)
endif

GCCVERSION     := $(shell $(CC) -dumpversion | cut -f1 -d.)
GCCMINOR       := $(shell $(CC) -dumpversion | cut -f2 -d.)
GCCMACHINE     := $(shell $(CC) -dumpmachine)
GCCNEWENOUGH   := $(shell ( [ $(GCCVERSION) -gt "4" ]        \
                          || ( [ $(GCCVERSION) -eq "4" ]     \
                              && [ $(GCCMINOR) -ge "7" ] ) ) \
                        && echo 1)
ifneq ($(GCCNEWENOUGH),1)
  $(error You need GCC 4.7 or later)
endif

ifneq ($(GCC_ARCH),$(findstring $(GCC_ARCH), $(GCCMACHINE)))
  $(error The selected compiler ($(CC)) is not set for $(ARCH))
endif

.PHONY: all clean superclean
all: $(GNUEFI_DIR)/$(GNUEFI_ARCH)/lib/libefi.a main.efi

$(GNUEFI_DIR)/$(GNUEFI_ARCH)/lib/libefi.a:
	$(MAKE) -C$(GNUEFI_DIR) CROSS_COMPILE=$(CROSS_COMPILE) ARCH=$(GNUEFI_ARCH) $(GNUEFI_LIBS)

NOOBJ=\
	efi_selftest_bitblt.o \
	efi_selftest_config_table.o \
	efi_selftest_controllers.o \
	efi_selftest_crc32.o \
	efi_selftest_devicepath.o \
	efi_selftest_devicepath_util.o \
	efi_selftest_event_groups.o \
	efi_selftest_events.o \
	efi_selftest_exitbootservices.o \
	efi_selftest_fdt.o \
	efi_selftest_gop.o \
	efi_selftest_loaded_image.o \
	efi_selftest_manageprotocols.o \
	efi_selftest_miniapp_exit.o \
	efi_selftest_miniapp_return.o \
	efi_selftest_snp.o \
	efi_selftest_startimage_exit.o \
	efi_selftest_startimage_return.o \
	efi_selftest_textinput.o \
	efi_selftest_textinputex.o \
	efi_selftest_textoutput.o \
	efi_selftest_tpl.o \
	efi_selftest_unaligned.o \
	efi_selftest_unicode_collation.o \
	efi_selftest_variables.o \
	efi_selftest_watchdog.o \

OBJ=\
	main.o \
	efi_selftest.o \
	efi_selftest_block_device.o \
	efi_selftest_console.o \
	efi_selftest_rtc.o \
	efi_selftest_util.o \

$(OBJ):  efi_selftest.h

main.efi: $(OBJ)
	@echo  [LD]  $(notdir $@)
	$(CC) $(LDFLAGS) $(OBJ) -o $@ $(LIBS)

# until we get rid of the bullshit u-boot UEFI_GUID macro ... -Wno-overflow
%.o: %.c
	@echo  [CC]  $(notdir $@)
	$(CC) -E -I. $(CFLAGS) -ffreestanding -Wno-unused-function -Wno-shadow -Wno-unused-variable -o $<.cpp $<
	$(CC) -I. $(CFLAGS) -ffreestanding -Wno-overflow -Wno-unused-function -Wno-shadow -Wno-unused-variable -c $<

qemu: CFLAGS += -D_DEBUG
qemu: all $(FW_BASE)_$(FW_ARCH).fd image/efi/boot/boot$(ARCH).efi
	$(QEMU) $(QEMU_OPTS) -bios ./$(FW_BASE)_$(FW_ARCH).fd -net none -hda fat:rw:image

image/efi/boot/boot$(ARCH).efi: main.efi
	mkdir -p image/efi/boot
	cp -f $< $@

$(FW_BASE)_$(FW_ARCH).fd:
	wget https://efi.akeo.ie/$(FW_BASE)/$(FW_ZIP)
	unzip $(FW_ZIP) $(FW_BASE).fd
	mv $(FW_BASE).fd $(FW_BASE)_$(FW_ARCH).fd
	rm $(FW_ZIP)

clean:
	rm -f main.efi *.o
	rm -rf image

superclean: clean
	$(MAKE) -C$(GNUEFI_DIR) ARCH=$(GNUEFI_ARCH) clean
	rm -f *.fd
