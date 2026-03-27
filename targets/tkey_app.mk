# Target file

# Target name
TARGET := tkey_app

# Programs to use for the target
TARGET_AR      := llvm-ar
#TARGET_AS      := llvm-as
TARGET_AS      := $(CC) -x assembler-with-cpp
TARGET_CC      := $(CC)
TARGET_CXX     :=
TARGET_LD      := lld
TARGET_OBJCOPY := llvm-objcopy # Set if a binary file should be created
TARGET_OBJDUMP := llvm-objdump # Set if a dump file should be created

LIBDIR := ../tkey-libs

# Source files for the target
TARGET_SRCS := \
               crypto/cifra/src/blockwise.c                       \
               crypto/cifra/src/sha512.c                          \
               crypto/sha256/sha256.c                             \
               crypto/tiny-AES-c/aes.c                            \
               fido2/apdu.c                                       \
               fido2/crypto.c                                     \
               fido2/ctap.c                                       \
               fido2/ctaphid.c                                    \
               fido2/ctap_parse.c                                 \
               fido2/extensions/extensions.c                      \
               fido2/log.c                                        \
               fido2/stubs.c                                      \
               fido2/test_power.c                                 \
               fido2/u2f.c                                        \
               fido2/util.c                                       \
               fido2/version.c                                    \
               targets/tkey/src/attestation.c                     \
               targets/tkey/src/device.c                          \
               targets/tkey/src/fifo.c                            \
               targets/tkey/src/init.c                            \
               targets/tkey/src/main.c                            \
               targets/tkey/src/rng.c                             \
               targets/tkey/src/fs.c                             \
               targets/tkey/libc/newlib/libc/search/qsort.c       \
               targets/tkey/libc/newlib/libc/string/memcmp.c      \
               targets/tkey/libc/newlib/libc/string/memcpy.c      \
               targets/tkey/libc/newlib/libc/string/memmove.c     \
               targets/tkey/libc/newlib/libc/string/memset.c      \
               targets/tkey/libc/newlib/libc/string/strcmp.c      \
               targets/tkey/libc/newlib/libc/string/strlen.c      \
               targets/tkey/libc/newlib/libc/string/strncmp.c     \
               targets/tkey/libc/abort.c                          \
               targets/tkey/libc/exit.c                           \
               targets/tkey/libc/stdio.c                          \
               targets/tkey/printf-embedded/printf-emb.c          \
               tinycbor/src/cborencoder.c                         \
               tinycbor/src/cborencoder_close_container_checked.c \
               tinycbor/src/cborerrorstrings.c                    \
               tinycbor/src/cborparser.c                          \

# Target-specific ARFLAGS
TARGET_ARFLAGS :=

# Target-specific ASFLAGS
TARGET_ASFLAGS := \
                  -c \
                  -MD \
                  -target riscv32-unknown-none-elf \
                  -march=rv32iczmmul \
                  -mabi=ilp32 \
                  -mcmodel=medany \
                  -ffunction-sections \
                  -fdata-sections \
                  -fomit-frame-pointer \
                  -mno-relax

ifdef QEMU
TARGET_ASFLAGS += -O0
TARGET_ASFLAGS += -g3
else
TARGET_ASFLAGS += -Os
endif

# Target-specific CFLAGS
TARGET_CFLAGS := \
                 -c \
                 -MD \
                 -target riscv32-unknown-none-elf \
                 -march=rv32iczmmul \
                 -mabi=ilp32 \
                 -mcmodel=medany \
                 -ffunction-sections \
                 -fdata-sections \
                 -fomit-frame-pointer \
                 -fno-builtin-printf \
                 -fno-builtin-putchar \
                 -ffast-math \
                 -fno-common \
                 -mno-relax \
                 -Wall \
                 -Werror=implicit-function-declaration

#TARGET_CFLAGS += -Wextra         # Gives lots of new warnings
#TARGET_CFLAGS += -pedantic       # Gives lots of new warnings
#TARGET_CFLAGS += -std=c99        # Gives errors

ifdef QEMU
TARGET_CFLAGS += -O0
TARGET_CFLAGS += -g3
else
TARGET_CFLAGS += -Os
TARGET_CFLAGS += -flto
endif

# Target-specific CXXFLAGS
TARGET_CXXFLAGS :=

# Target-specific LDFLAGS
TARGET_LDFLAGS := \
                  -target riscv32-unknown-none-elf \
                  -march=rv32iczmmul \
                  -mabi=ilp32 \
                  -mcmodel=medany \
                  -static \
                  -nostdlib \
                  -flto \
                  -fuse-ld=$(TARGET_LD) \
                  -Wl,--cref,-M \
                  -Wl,-mllvm,-mattr=+c,-mllvm,-mattr=+zmmul \
                  -Wl,--gc-sections

# Target-specific OBJCOPY FLAGS
TARGET_OBJCOPYFLAGS := \
                       --input-target=elf32-littleriscv \
                       --output-target=binary

# Target-specific OBJDUMP FLAGS
TARGET_OBJDUMPFLAGS := \
                       -S \
                       -d

# Target-specific DEFINES
TARGET_DEFINES := \
                  -DAES256=1 \
                  -DAPP_CONFIG=\"app.h\" \
                  -DuECC_PLATFORM=0

ifdef QEMU
TARGET_DEFINES += -DDEBUG_LEVEL=1
else
TARGET_DEFINES += -DDEBUG_LEVEL=0
endif

TARGET_DEFINES += -DLFS_NO_MALLOC
ifdef QEMU
TARGET_DEFINES += -DLFS_YES_TRACE
TARGET_DEFINES += -DENABLE_PRINTF
#TARGET_DEFINES += -DTKEY_DEBUG
TARGET_DEFINES += -DQEMU_DEBUG
endif

# Target-specific INCLUDES
TARGET_INCLUDES := \
                   -Icrypto/cifra/src \
                   -Icrypto/cifra/src/ext \
                   -Icrypto/micro-ecc \
                   -Icrypto/sha256 \
                   -Icrypto/tiny-AES-c \
                   -Ifido2 \
                   -Ifido2/extensions \
                   -Itargets/tkey/inc \
                   -Itargets/tkey/libc/include \
                   -Itargets/tkey/libc/newlib/libc/include \
                   -Itargets/tkey/printf-embedded \
                   -Itinycbor/src \
                   -I$(LIBDIR)/include \
                   -I$(LIBDIR)/monocypher \
                   -I$(LIBDIR)/littlefs

# Target-specific EXTERNAL LIBRARIES to be included
TARGET_EXT_LIBS := \
                   $(LIBDIR)/libcrt0.a \
                   $(LIBDIR)/libcommon.a \
                   $(LIBDIR)/libsyscall.a \
                   $(LIBDIR)/libmonocypher.a \
                   $(LIBDIR)/liblfs.a

# Target-specific LINKER SCRIPT

ifdef QEMU
TARGET_LINKER_SCRIPT := \
                        targets/tkey/linker/tkey_qemu.ld
else
TARGET_LINKER_SCRIPT := \
                        targets/tkey/linker/tkey.ld
endif

# Target-specific SHELL COMMAND to execute before build start
TARGET_PREBUILD_CMD :=

# Target-specific SHELL COMMAND to execute after build finish
TARGET_POSTBUILD_CMD :=

# Targets to build before this target is built
ifdef QEMU
TARGET_NEEDS_TARGETS := tkey_uecc_debug.a
else
TARGET_NEEDS_TARGETS := tkey_uecc.a
endif

# Add the target to the global list of targets
TARGETS += $(TARGET)

### Define target-specific variables ###
$(TARGET)_AR             := $(TARGET_AR)
$(TARGET)_AS             := $(TARGET_AS)
$(TARGET)_CC             := $(TARGET_CC)
$(TARGET)_LD             := $(TARGET_LD)
$(TARGET)_OBJCOPY        := $(TARGET_OBJCOPY)
$(TARGET)_OBJDUMP        := $(TARGET_OBJDUMP)

$(TARGET)_SRCS           := $(TARGET_SRCS)

# Object files for the target
TARGET_OBJS              := $(patsubst %.c,%.o,$(TARGET_SRCS))
TARGET_OBJS              := $(patsubst %.S,%.o,$(TARGET_OBJS))
$(TARGET)_OBJS           := $(TARGET_OBJS)

$(TARGET)_ARFLAGS        := $(TARGET_ARFLAGS)
$(TARGET)_ASFLAGS        := $(TARGET_ASFLAGS)
$(TARGET)_CFLAGS         := $(TARGET_CFLAGS)
$(TARGET)_LDFLAGS        := $(TARGET_LDFLAGS)
$(TARGET)_OBJCOPYFLAGS   := $(TARGET_OBJCOPYFLAGS)
$(TARGET)_OBJDUMPFLAGS   := $(TARGET_OBJDUMPFLAGS)

$(TARGET)_DEFINES        := $(TARGET_DEFINES)
$(TARGET)_INCLUDES       := $(TARGET_INCLUDES)
$(TARGET)_EXT_LIBS       := $(TARGET_EXT_LIBS)
$(TARGET)_LINKER_SCRIPT  := $(addprefix -T,$(TARGET_LINKER_SCRIPT))

$(TARGET)_PREBUILD_CMD   := $(TARGET_PREBUILD_CMD)
$(TARGET)_POSTBUILD_CMD  := $(TARGET_POSTBUILD_CMD)
$(TARGET)_NEEDS_TARGETS  := $(TARGET_NEEDS_TARGETS)

