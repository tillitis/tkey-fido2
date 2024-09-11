# Target file

# Target name
TARGET := solokeys_linux

# Programs to use for the target
TARGET_AR      :=
TARGET_AS      := as
TARGET_CC      := gcc
TARGET_CXX     :=
TARGET_LD      := ld
TARGET_OBJCOPY := # Set if a binary file should be created
TARGET_OBJDUMP := # Set if a dump file should be created

# Source files for the target
TARGET_SRCS := \
               pc/device.c \
               pc/main.c

# Target-specific ARFLAGS
TARGET_ARFLAGS :=

# Target-specific ASFLAGS
TARGET_ASFLAGS :=

# Target-specific CFLAGS
TARGET_CFLAGS := \
                 -c \
                 -fcommon \
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
                  -Wl,--cref,-M \
                  -Wl,--gc-sections

# Target-specific OBJCOPY FLAGS
TARGET_OBJCOPYFLAGS := \
                       -O binary

# Target-specific OBJDUMP FLAGS
TARGET_OBJDUMPFLAGS := \
                       -S \
                       -d

# Target-specific DEFINES
TARGET_DEFINES := \
                  -DDEBUG_LEVEL=2

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
                   -Itinycbor/src \
                   -Ipc

# Target-specific EXTERNAL LIBRARIES to be included
TARGET_EXT_LIBS :=

# Target-specific LINKER SCRIPT
TARGET_LINKER_SCRIPT :=

# Target-specific SHELL COMMAND to execute before build start
TARGET_PREBUILD_CMD :=

# Target-specific SHELL COMMAND to execute after build finish
TARGET_POSTBUILD_CMD :=

# Targets to build before this target is built
TARGET_NEEDS_TARGETS := \
                         libsolokeys_linux.a

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

