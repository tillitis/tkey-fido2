# Target file

# Target name
TARGET := tkey_app

# Programs to use for the target
TARGET_AR      := llvm-ar-16
#TARGET_AS      := llvm-as-16
TARGET_AS      := clang-16 -x assembler-with-cpp
TARGET_CC      := clang-16
TARGET_CXX     :=
TARGET_LD      := lld-16
TARGET_OBJCOPY := llvm-objcopy-16 # Set if a binary file should be created
TARGET_OBJDUMP := llvm-objdump-16 # Set if a dump file should be created

# Source files for the target
TARGET_SRCS := \
               crypto/cifra/src/blockwise.c                       \
               crypto/cifra/src/sha512.c                          \
               crypto/micro-ecc/uECC.c                            \
               crypto/sha256/sha256.c                             \
               crypto/tiny-AES-c/aes.c                            \
               crypto/tweetnacl/tweetnacl.c                       \
               fido2/apdu.c                                       \
               fido2/crypto.c                                     \
               fido2/ctap.c                                       \
               fido2/ctaphid.c                                    \
               fido2/ctap_parse.c                                 \
               fido2/data_migration.c                             \
               fido2/extensions/extensions.c                      \
               fido2/extensions/solo.c                            \
               fido2/extensions/wallet.c                          \
               fido2/log.c                                        \
               fido2/stubs.c                                      \
               fido2/test_power.c                                 \
               fido2/u2f.c                                        \
               fido2/util.c                                       \
               fido2/version.c                                    \
               targets/tkey/src/attestation.c                     \
               targets/tkey/src/device.c                          \
               targets/tkey/src/fifo.c                            \
               targets/tkey/src/flash.c                           \
               targets/tkey/src/init.c                            \
               targets/tkey/src/led.c                             \
               targets/tkey/src/main.c                            \
               targets/tkey/src/redirect.c                        \
               targets/tkey/src/rng.c                             \
               targets/tkey/src/sense.c                           \
               targets/tkey/newlib-quekto/src/assert.c            \
               targets/tkey/newlib-quekto/src/math.c              \
               targets/tkey/newlib-quekto/src/stdio.c             \
               targets/tkey/newlib-quekto/src/stdlib.c            \
               targets/tkey/newlib-quekto/src/string.c            \
               tinycbor/src/cborencoder.c                         \
               tinycbor/src/cborencoder_close_container_checked.c \
               tinycbor/src/cborerrorstrings.c                    \
               tinycbor/src/cborparser.c                          \
               tinycbor/src/cborparser_dup_string.c               \
               tinycbor/src/cborpretty.c                          \
               tinycbor/src/cborpretty_stdio.c                    \
               tinycbor/src/cbortojson.c                          \
               tinycbor/src/cborvalidation.c

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
                 -ggdb3 \
                 -O0

# Target-specific CFLAGS
TARGET_CFLAGS := \
                 -c \
                 -MD \
                 -target riscv32-unknown-none-elf \
                 -march=rv32iczmmul \
                 -mabi=ilp32 \
                 -mcmodel=medany \
                 -Os \
                 -ffast-math \
                 -fno-common \
                 -fno-builtin-printf \
                 -fno-builtin-putchar \
                 -nostdlib \
                 -mno-relax \
                 -g \
                 -Wall \
                 -Werror=implicit-function-declaration \
                 -static \
                 -flto 

#                 -std=c99 \

#                 -c \
                 -ffunction-sections \
                 -fdata-sections \
                 -fomit-frame-pointer \
                 -ggdb3 \
                 -MD \
                 -O0 \
                 -Wno-unused-parameter \
                 -Wno-missing-field-initializers \
                 -Wall \
                 -target riscv32-unknown-none-elf \
                 -march=rv32iczmmul \
                 -mabi=ilp32 \
                 -mcmodel=medany \
                 -static \
                 -std=gnu99 \
                 -ffast-math \
                 -fno-common \
                 -fno-builtin-printf \
                 -fno-builtin-putchar \
                 -mno-relax \
                 -Werror=implicit-function-declaration \
                 -opaque-pointers \
                 -nostdlib \
                 -flto

# Target-specific CXXFLAGS
TARGET_CXXFLAGS := 

# Target-specific LDFLAGS
TARGET_LDFLAGS := \
                  -target riscv32-unknown-none-elf \
                  -march=rv32iczmmul \
                  -mabi=ilp32 \
                  -mcmodel=medany \
                  -static \
                  -std=gnu99 \
                  -Os \
                  -ffast-math \
                  -fno-common \
                  -fno-builtin-printf \
                  -fno-builtin-putchar \
                  -nostdlib \
                  -nodefaultlibs \
                  -mno-relax \
                  -g \
                  -Wall \
                  -Werror=implicit-function-declaration \
                  -flto \
                  -fuse-ld=lld-16 \
                  -Wl,--cref,-M \
                  -Wl,--gc-sections \

                  #-fuse-ld=lld-16 \
                  -target riscv32-unknown-none-elf \
                  -static \
                  -nostdlib \
                  -mno-relax \
                  -flto \
                  -Wl,--cref,-M \
                  -Wl,--gc-sections \
                  -v


#                  -target riscv32-unknown-none-elf \
                  -march=rv32iczmmul \
                  -mabi=ilp32 \
                  -mcmodel=medany \
                  -fuse-ld=lld-16 \
                  -nostdlib \
                  -Wl,--cref,-M \
                  -Wl,--gc-sections

#                  -L ../tkey-libs \
                  -lcommon \
                  -lcrt0 \

#                  -specs=nosys.specs
#                  -lc 
#                  -lm 

# 1. -specs=nosys.specs  Provides all syscall functions and _mainCRTStartup code that makes __libc_init_array work.
# 2. -specs=nano.specs   Same as nosys but slimmer libraries and not so many extra functions.
# 3. -nostartfiles       Do not use the standard system libraries when linking. Need to provide all syscall
#                        functions yourself and remove call to __libc_init_array.
# 4. -nostdlib           Do not use the standard system startup files or libraries when linking. Need to provide
#                        all syscall functions yourself and remove call to __libc_init_array.
#                        No startup files and only the libraries you specify are passed to the linker, and
#                        options specifying linkage of the system libraries, such as -static-libgcc or
#                        -shared-libgcc, are ignored.
#                        The compiler may generate calls to "memcmp", "memset", "memcpy" and "memmove". These
#                        entries are usually resolved by entries in libc. These entry points should be supplied
#                        through some other mechanism when this option is specified.
#                        One of the standard libraries bypassed by -nostdlib and -nodefaultlibs is libgcc.a, a
#                        library of internal subroutines which GCC uses to overcome shortcomings of particular
#                        machines, or special needs for some languages. In most cases, you need libgcc.a even
#                        when you want to avoid other standard libraries. In other words, when you specify
#                        -nostdlib or -nodefaultlibs you should usually specify -lgcc as well. This ensures
#                        that you have no unresolved references to internal GCC library subroutines. (An example
#                        of such an internal subroutine is "__main", used to ensure C++ constructors are called.)
# Summary: Nicest code layout is given by -nostartfiles

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
                  -DDEBUG_LEVEL=2 \
                  -DuECC_PLATFORM=0 \
                  -DQEMU_DEBUG

# Target-specific INCLUDES
TARGET_INCLUDES := \
                   -Icrypto/cifra/src \
                   -Icrypto/cifra/src/ext \
                   -Icrypto/micro-ecc \
                   -Icrypto/sha256 \
                   -Icrypto/tiny-AES-c \
                   -Icrypto/tweetnacl \
                   -Ifido2 \
                   -Ifido2/extensions \
                   -Itargets/tkey/inc \
                   -Itargets/tkey/newlib-quekto/inc \
                   -Itinycbor/src \
                   -I../tkey-libs/include

# Target-specific EXTERNAL LIBRARIES to be included
TARGET_EXT_LIBS := \
                   ../tkey-libs/libcrt0.a \
                   ../tkey-libs/libcommon.a

# Target-specific LINKER SCRIPT
TARGET_LINKER_SCRIPT := \
                        targets/tkey/linker/tkey.ld

# Target-specific SHELL COMMAND to execute before build start
TARGET_PREBUILD_CMD :=

# Target-specific SHELL COMMAND to execute after build finish
TARGET_POSTBUILD_CMD :=

# Targets to build before this target is built
TARGET_NEEDS_TARGETS :=

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

