# SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
# SPDX-License-Identifier: Apache-2.0 OR MIT

# Target file

# Target name
TARGET := tkey_lfs.a

# Programs to use for the target
TARGET_AR      := llvm-ar
TARGET_AS      := $(CC) -x assembler-with-cpp
TARGET_CC      := $(CC)
TARGET_CXX     :=
TARGET_LD      := lld
TARGET_OBJCOPY := llvm-objcopy # Set if a binary file should be created
TARGET_OBJDUMP := llvm-objdump # Set if a dump file should be created

LIBDIR := ../tkey-libs

# Source files for the target
TARGET_SRCS := \
               lfs/lfs.c \
               lfs/lfs_util.c \

# Target-specific ARFLAGS
TARGET_ARFLAGS := \
                  r

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
                  -fomit-frame-pointer

TARGET_ASFLAGS += -mno-relax
TARGET_ASFLAGS += -Os

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
                 -Wall \
                 -Werror=implicit-function-declaration

#TARGET_CFLAGS += -Wextra         # Gives lots of new warnings
#TARGET_CFLAGS += -pedantic       # Gives lots of new warnings
#TARGET_CFLAGS += -std=c99        # Gives errors

TARGET_CFLAGS += -mno-relax
TARGET_CFLAGS += -Os
TARGET_CFLAGS += -flto

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
                    -D LFS_NO_MALLOC \
                    -D LFS_NO_DEBUG \
                    -D LFS_NO_WARN \
                    -D LFS_NO_ERROR

# Target-specific INCLUDES
TARGET_INCLUDES := \
                    -Ilfs/ \
                    -I$(LIBDIR)/include \
                    -Itargets/tkey/libc/include

# Target-specific EXTERNAL LIBRARIES to be included
TARGET_EXT_LIBS :=

# Target-specific LINKER SCRIPT
TARGET_LINKER_SCRIPT :=

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
