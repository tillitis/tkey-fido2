# Target file

# Target name
TARGET := tkey_uecc.a

# Programs to use for the target
TARGET_AR      := llvm-ar
TARGET_AS      := clang -x assembler-with-cpp
TARGET_CC      := clang
TARGET_CXX     :=
TARGET_LD      := lld
TARGET_OBJCOPY := llvm-objcopy # Set if a binary file should be created
TARGET_OBJDUMP := llvm-objdump # Set if a dump file should be created

# Source files for the target
TARGET_SRCS := \
               crypto/micro-ecc/uECC.c

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
                 -fomit-frame-pointer \
                 -ggdb3 \
                 -O2

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
                  -Wl,-mllvm,-mattr=+c,-mllvm,-mattr=+zmmul \
                  -Wl,--gc-sections \

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
                  -DuECC_PLATFORM=0 \

# Target-specific INCLUDES
TARGET_INCLUDES := \
                   -Icrypto/micro-ecc

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

