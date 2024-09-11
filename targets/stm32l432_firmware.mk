# Target file

# Target name
TARGET := stm32l432_firmware

# Programs to use for the target
TARGET_AR      := arm-none-eabi-ar
TARGET_AS      := arm-none-eabi-gcc -x assembler-with-cpp
TARGET_CC      := arm-none-eabi-gcc
TARGET_CXX     :=
TARGET_LD      := arm-none-eabi-ld
TARGET_OBJCOPY := arm-none-eabi-objcopy # Set if a binary file should be created
TARGET_OBJDUMP := arm-none-eabi-objdump # Set if a dump file should be created

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
               targets/stm32l432/lib/stm32l4xx_hal_pcd.c          \
               targets/stm32l432/lib/stm32l4xx_hal_pcd_ex.c       \
               targets/stm32l432/lib/stm32l4xx_ll_exti.c          \
               targets/stm32l432/lib/stm32l4xx_ll_gpio.c          \
               targets/stm32l432/lib/stm32l4xx_ll_pwr.c           \
               targets/stm32l432/lib/stm32l4xx_ll_rcc.c           \
               targets/stm32l432/lib/stm32l4xx_ll_rng.c           \
               targets/stm32l432/lib/stm32l4xx_ll_spi.c           \
               targets/stm32l432/lib/stm32l4xx_ll_tim.c           \
               targets/stm32l432/lib/stm32l4xx_ll_usart.c         \
               targets/stm32l432/lib/stm32l4xx_ll_usb.c           \
               targets/stm32l432/lib/stm32l4xx_ll_utils.c         \
               targets/stm32l432/lib/usbd/usbd_ccid.c             \
               targets/stm32l432/lib/usbd/usbd_cdc.c              \
               targets/stm32l432/lib/usbd/usbd_cdc_if.c           \
               targets/stm32l432/lib/usbd/usbd_composite.c        \
               targets/stm32l432/lib/usbd/usbd_conf.c             \
               targets/stm32l432/lib/usbd/usbd_core.c             \
               targets/stm32l432/lib/usbd/usbd_ctlreq.c           \
               targets/stm32l432/lib/usbd/usbd_desc.c             \
               targets/stm32l432/lib/usbd/usbd_hid.c              \
               targets/stm32l432/lib/usbd/usbd_ioreq.c            \
               targets/stm32l432/src/ams.c                        \
               targets/stm32l432/src/attestation.c                \
               targets/stm32l432/src/device.c                     \
               targets/stm32l432/src/fifo.c                       \
               targets/stm32l432/src/flash.c                      \
               targets/stm32l432/src/init.c                       \
               targets/stm32l432/src/led.c                        \
               targets/stm32l432/src/main.c                       \
               targets/stm32l432/src/nfc.c                        \
               targets/stm32l432/src/redirect.c                   \
               targets/stm32l432/src/rng.c                        \
               targets/stm32l432/src/sense.c                      \
               targets/stm32l432/src/startup_stm32l432xx.S        \
               targets/stm32l432/src/system_stm32l4xx.c           \
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
                  -mcpu=cortex-m4 \
                  -mfpu=fpv4-sp-d16 \
                  -mfloat-abi=hard \
                  -mthumb \
                  -ffunction-sections \
                  -fdata-sections \
                  -fomit-frame-pointer \
                  -ggdb3 \
                  -MD \
                  -O0

# Target-specific CFLAGS
TARGET_CFLAGS := \
                 -c \
                 -mcpu=cortex-m4 \
                 -mfpu=fpv4-sp-d16 \
                 -mfloat-abi=hard \
                 -mthumb \
                 -fdata-sections \
                 -ffunction-sections \
                 -fomit-frame-pointer \
                 -ggdb3 \
                 -MD \
                 -O0 \
                 -Wall \
                 -Wno-missing-field-initializers \
                 -Wno-unused-parameter

# Target-specific CXXFLAGS
TARGET_CXXFLAGS := 

# Target-specific LDFLAGS
TARGET_LDFLAGS := \
                  -mcpu=cortex-m4 \
                  -mfpu=fpv4-sp-d16 \
                  -mfloat-abi=hard \
                  -mthumb \
                  -specs=nosys.specs \
                  -lc \
                  -lm \
                  -Wl,--cref,-M \
                  -Wl,--gc-sections

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
                       -O binary

# Target-specific OBJDUMP FLAGS
TARGET_OBJDUMPFLAGS := \
                       -S \
                       -d

# Target-specific DEFINES
TARGET_DEFINES := \
                  -DSTM32L432xx \
                  -DAES256=1 \
                  -DUSE_FULL_LL_DRIVER \
                  -DAPP_CONFIG=\"app.h\" \
                  -DDEBUG_LEVEL=2 \
                  -DuECC_PLATFORM=5 \
                  -DuECC_OPTIMIZATION_LEVEL=4 \
                  -DuECC_SQUARE_FUNC=1 \
                  -DuECC_SUPPORT_COMPRESSED_POINT=0

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
                   -Itargets/stm32l432/lib \
                   -Itargets/stm32l432/lib/usbd \
                   -Itargets/stm32l432/src \
                   -Itargets/stm32l432/src/cmsis \
                   -Itinycbor/src

# Target-specific EXTERNAL LIBRARIES to be included
TARGET_EXT_LIBS :=

# Target-specific LINKER SCRIPT
TARGET_LINKER_SCRIPT := \
                        targets/stm32l432/linker/stm32l4xx.ld

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

