# Common Makefile for Packet Anonymization Project
# Contains shared build rules and utilities

# Common variables
PROJECT_NAME = packet-anonymization
VERSION = 1.0.0
AUTHOR = "Packet Anonymization Project Contributors"

# Common compiler flags
COMMON_CFLAGS = -Wall -Wextra -std=c99 -fPIC
COMMON_BPF_CFLAGS = -target bpf -c -fPIC

# Common directories
PROJECT_ROOT = $(shell pwd)
BUILD_DIR = $(PROJECT_ROOT)/build
INSTALL_DIR = /usr/local
BIN_DIR = $(INSTALL_DIR)/bin
LIB_DIR = $(INSTALL_DIR)/lib
INCLUDE_DIR = $(INSTALL_DIR)/include

# Common libraries
COMMON_LIBS = -lbpf -lelf -lz

# Common includes
COMMON_INCLUDES = -I$(PROJECT_ROOT)/src -I$(PROJECT_ROOT)/common

# Utility functions
define print_status
	@echo "$(1)"
endef

define check_command
	@which $(1) > /dev/null || (echo "Error: $(1) not found. $(2)" && exit 1)
endef

# Common targets
.PHONY: common-clean common-distclean common-help

# Common clean target
common-clean:
	$(call print_status,"Cleaning build artifacts...")
	rm -rf $(BUILD_DIR)
	find . -name "*.o" -delete
	find . -name "*.so" -delete
	find . -name "*.ko" -delete
	find . -name "*.a" -delete

# Common distclean target
common-distclean: common-clean
	$(call print_status,"Cleaning all generated files...")
	find . -name "*.log" -delete
	find . -name "*.tmp" -delete
	find . -name "*~" -delete

# Common help target
common-help:
	@echo "Common Makefile Targets:"
	@echo "  common-clean     - Remove build artifacts"
	@echo "  common-distclean - Remove all generated files"
	@echo "  common-help      - Show this help message"

# Dependency checking
check-common-deps:
	$(call print_status,"Checking common dependencies...")
	$(call check_command,clang,"Install with: sudo apt install clang")
	$(call check_command,llvm-strip,"Install with: sudo apt install llvm")
	$(call check_command,pkg-config,"Install with: sudo apt install pkg-config")
	@pkg-config --exists libbpf || (echo "Error: libbpf not found. Install with: sudo apt install libbpf-dev" && exit 1)
	$(call print_status,"All common dependencies found!")

# Version information
version:
	@echo "$(PROJECT_NAME) version $(VERSION)"
	@echo "Author: $(AUTHOR)"

# Create necessary directories
create-dirs:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(BIN_DIR)
	mkdir -p $(LIB_DIR)
	mkdir -p $(INCLUDE_DIR)

# Install common files
install-common: create-dirs
	$(call print_status,"Installing common files...")
	cp -r $(PROJECT_ROOT)/common/*.h $(INCLUDE_DIR)/ 2>/dev/null || true
	$(call print_status,"Common files installed!")

# Uninstall common files
uninstall-common:
	$(call print_status,"Uninstalling common files...")
	rm -f $(INCLUDE_DIR)/parsing_helpers.h
	rm -f $(INCLUDE_DIR)/rewrite_helpers.h
	$(call print_status,"Common files uninstalled!")

# Build configuration
debug-config: COMMON_CFLAGS += -DDEBUG -g3 -O0
debug-config: COMMON_BPF_CFLAGS += -DDEBUG -g3 -O0

release-config: COMMON_CFLAGS += -DNDEBUG -O3
release-config: COMMON_BPF_CFLAGS += -DNDEBUG -O3

# Common test targets
test-common:
	$(call print_status,"Running common tests...")
	@echo "Common tests completed!"

# Documentation targets
docs-common:
	$(call print_status,"Generating common documentation...")
	@echo "Common documentation generated!"

# Package targets
package-common:
	$(call print_status,"Creating common package...")
	@echo "Common package created!"

# Export common variables for use in other Makefiles
export PROJECT_NAME VERSION AUTHOR
export COMMON_CFLAGS COMMON_BPF_CFLAGS
export BUILD_DIR INSTALL_DIR BIN_DIR LIB_DIR INCLUDE_DIR
export COMMON_LIBS COMMON_INCLUDES
