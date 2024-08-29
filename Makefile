# Main Makefile

# Directories for object files and binaries
OBJDIR := _obj
BINDIR := _bin

# Ensure directories exist
$(shell mkdir -p $(OBJDIR) $(BINDIR))

# List of target files
TARGET_FILES := $(wildcard targets/*.mk)

# Global target list
TARGETS := 

# Include target files
include $(TARGET_FILES)

# Default target
all: $(TARGETS)

# Build rules for each target
define BUILD_RULE
# If target name ends with '.a' we make a library
ifeq "$(suffix $(1))" ".a"
    $(1): $(1)-prebuild_cmd $(BINDIR)/$(1)/$(1) $(1)-postbuild_cmd
        $(1)-prebuild_cmd:
	        $($(1)_PREBUILD_CMD)
        $(BINDIR)/$(1)/$(1): $(addprefix $(OBJDIR)/$(1)/,$($(1)_OBJS))
	        mkdir -p $$(dir $$@)
            ifneq "$($(1)_AR)" ""
	            $($(1)_AR) $($(1)_ARFLAGS) $$@ $(addprefix $(OBJDIR)/$(1)/,$($(1)_OBJS))
            else
	            @echo AR command missing for $(1)
	            @exit 1
            endif
        $(1)-postbuild_cmd:
	        $($(1)_POSTBUILD_CMD)
# Otherwise we link
else
    $(1): $(1)-prebuild_cmd $(BINDIR)/$(1)/$(1) $(1)-postbuild_cmd
        $(1)-prebuild_cmd:
	        $($(1)_PREBUILD_CMD)
        $(BINDIR)/$(1)/$(1): $(addprefix $(OBJDIR)/$(1)/,$($(1)_OBJS)) \
                             $(foreach target,$($(1)_NEEDS_TARGETS),$(BINDIR)/$(target)/$(target)) \
                             $($(1)_EXT_LIBS)
	        @mkdir -p $$(dir $$@)
	        $($(1)_CC) $($(1)_LDFLAGS) -o $$@ \
	                                   $(addprefix $(OBJDIR)/$(1)/,$($(1)_OBJS)) \
                              $(foreach target,$($(1)_NEEDS_TARGETS),$(BINDIR)/$(target)/$(target)) \
                              $($(1)_EXT_LIBS) \
                              $($(1)_LINKER_SCRIPT) \
                              > $(BINDIR)/$(1)/$(1).map
            ifneq "$($(1)_OBJDUMP)" ""
	            $($(1)_OBJDUMP) $($(1)_OBJDUMPFLAGS) $$@ >$(BINDIR)/$(1)/$(1).dmp
            endif
            ifneq "$($(1)_OBJCOPY)" ""
	            $($(1)_OBJCOPY) $($(1)_OBJCOPYFLAGS) $$@ $$@.bin
            endif
        $(1)-postbuild_cmd:
	        $($(1)_POSTBUILD_CMD)
endif
endef

# Apply build rules for each target
$(foreach target, $(TARGETS), $(eval $(call BUILD_RULE,$(target))))

# Compilation rules for each object file
define COMPILE_RULE
$(OBJDIR)/$(1)/%.o: %.c
	@mkdir -p $$(dir $$@)
	$$($(1)_CC) $$($(1)_CFLAGS) $$($(1)_DEFINES) $$($(1)_INCLUDES) -o $$@ $$<
$(OBJDIR)/$(1)/%.o: %.cpp # Extend to .C, .cc, .cpp, .CPP, .c++, .cp, or .cxx?
	@mkdir -p $$(dir $$@)
	$$($(1)_CXX) $$($(1)_CXXFLAGS) $$($(1)_DEFINES) $$($(1)_INCLUDES) -o $$@ $$<
$(OBJDIR)/$(1)/%.o: %.S
	@mkdir -p $$(dir $$@)
	$$($(1)_AS) $$($(1)_ASFLAGS) $$($(1)_DEFINES) $$($(1)_INCLUDES) -o $$@ $$<
endef

# Apply compilation rules for each target
$(foreach target, $(TARGETS), $(eval $(call COMPILE_RULE,$(target))))

# Clean rule for each target
define CLEAN_RULE
clean: clean-$(1)
.PHONY: clean-$(1)
clean-$(1):
	rm -f $(BINDIR)/$(1)/$(1) \
          $(BINDIR)/$(1)/$(1).bin \
          $(BINDIR)/$(1)/$(1).dmp \
          $(BINDIR)/$(1)/$(1).map \
          $(addprefix $(OBJDIR)/$(1)/,$($(1)_OBJS:%.o=%.d)) \
          $(addprefix $(OBJDIR)/$(1)/,$($(1)_OBJS:%.o=%.o))
endef

# Help rule
define SHOW_TARGETS_RULE
	echo "$1";
endef

# Include dependency files if they exist
#-include $(wildcard $(OBJDIR)/*/*.d)

# Clean for a specific target
.PHONY: clean
$(foreach target,$(TARGETS), $(eval $(call CLEAN_RULE,$(target))))

# Clean-all rule
clean-all:
	rm -rf $(OBJDIR) $(BINDIR)

.PHONY: help
help:
	@echo "Available targets:"
	@$(foreach target,$(sort $(TARGETS)),$(call SHOW_TARGETS_RULE,$(target)))
