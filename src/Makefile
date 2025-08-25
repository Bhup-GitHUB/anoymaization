# Makefile for Packet Anonymization Project
# Builds eBPF kernel program and userspace control program

# Compiler and flags
CC = clang
CFLAGS = -g -O2 -Wall -Wextra -std=c99
BPF_CFLAGS = -g -O2 -target bpf -c

# Directories
SRC_DIR = .
COMMON_DIR = ../common
BUILD_DIR = ../build
INSTALL_DIR = /usr/local/bin

# Source files
KERN_SRC = $(SRC_DIR)/prog_kern.c
USER_SRC = $(SRC_DIR)/prog_userspace.c
COMMON_HEADERS = $(COMMON_DIR)/parsing_helpers.h $(COMMON_DIR)/rewrite_helpers.h
COMMON_STRUCTS = $(SRC_DIR)/common_structs.h

# Object files
KERN_OBJ = $(BUILD_DIR)/prog_kern.o
USER_OBJ = $(BUILD_DIR)/prog_userspace

# Dependencies
LIBS = -lbpf -lelf -lz
INCLUDES = -I$(SRC_DIR) -I$(COMMON_DIR)

# Default target
all: $(BUILD_DIR) $(KERN_OBJ) $(USER_OBJ)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build eBPF kernel program
$(KERN_OBJ): $(KERN_SRC) $(COMMON_HEADERS) $(COMMON_STRUCTS)
	$(CC) $(BPF_CFLAGS) $(INCLUDES) -o $@ $<

# Build userspace program
$(USER_OBJ): $(USER_SRC) $(COMMON_HEADERS) $(COMMON_STRUCTS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

# Install target
install: $(USER_OBJ)
	sudo cp $(USER_OBJ) $(INSTALL_DIR)/
	sudo chmod +x $(INSTALL_DIR)/prog_userspace
	@echo "Installed to $(INSTALL_DIR)/prog_userspace"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f *.o *.so *.ko

# Clean everything including generated files
distclean: clean
	rm -f $(USER_OBJ)
	rm -f $(KERN_OBJ)

# Check dependencies
check-deps:
	@echo "Checking build dependencies..."
	@which clang > /dev/null || (echo "Error: clang not found. Install with: sudo apt install clang" && exit 1)
	@which llvm-strip > /dev/null || (echo "Error: llvm-strip not found. Install with: sudo apt install llvm" && exit 1)
	@pkg-config --exists libbpf || (echo "Error: libbpf not found. Install with: sudo apt install libbpf-dev" && exit 1)
	@echo "All dependencies found!"

# Build with dependency check
build: check-deps all

# Test build (compile only)
test-build: check-deps $(KERN_OBJ) $(USER_OBJ)
	@echo "Build test successful!"

# Show help
help:
	@echo "Packet Anonymization Project Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build kernel and userspace programs (default)"
	@echo "  build        - Check dependencies and build"
	@echo "  install      - Install userspace program to system"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Remove all generated files"
	@echo "  check-deps   - Check if all dependencies are installed"
	@echo "  test-build   - Test compilation only"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make                    # Build everything"
	@echo "  sudo make install       # Install to system"
	@echo "  make clean              # Clean build files"
	@echo ""
	@echo "Dependencies:"
	@echo "  - clang/llvm"
	@echo "  - libbpf-dev"
	@echo "  - libelf-dev"
	@echo "  - zlib1g-dev"

# Phony targets
.PHONY: all build install clean distclean check-deps test-build help

# Debug target for development
debug: CFLAGS += -DDEBUG -g3
debug: BPF_CFLAGS += -DDEBUG -g3
debug: all

# Release target for production
release: CFLAGS += -DNDEBUG -O3
release: BPF_CFLAGS += -DNDEBUG -O3
release: all
