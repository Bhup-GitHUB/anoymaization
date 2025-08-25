#!/bin/bash

# Packet Anonymization Project - Dependency Installation Script
# This script installs all required dependencies for building and running the project

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "debian"
        elif command_exists yum; then
            echo "rhel"
        elif command_exists dnf; then
            echo "fedora"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to install dependencies on Debian/Ubuntu
install_debian() {
    print_status "Installing dependencies on Debian/Ubuntu..."
    
    # Update package list
    sudo apt-get update
    
    # Install build tools
    sudo apt-get install -y build-essential cmake pkg-config
    
    # Install LLVM/Clang
    sudo apt-get install -y clang llvm llvm-dev
    
    # Install BPF dependencies
    sudo apt-get install -y libbpf-dev libelf-dev zlib1g-dev
    
    # Install kernel headers
    sudo apt-get install -y linux-headers-$(uname -r)
    
    # Install additional tools
    sudo apt-get install -y git curl wget
    
    # Install XDP tools (optional)
    if [ ! -d "xdp-tools" ]; then
        print_status "Installing XDP tools..."
        git clone https://github.com/xdp-project/xdp-tools.git
        cd xdp-tools
        git submodule init && git submodule update
        ./configure
        make
        sudo make install
        cd ..
    fi
}

# Function to install dependencies on RHEL/CentOS
install_rhel() {
    print_status "Installing dependencies on RHEL/CentOS..."
    
    # Install EPEL repository
    sudo yum install -y epel-release
    
    # Install build tools
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y cmake pkg-config
    
    # Install LLVM/Clang
    sudo yum install -y clang llvm llvm-devel
    
    # Install BPF dependencies
    sudo yum install -y libbpf-devel elfutils-libelf-devel zlib-devel
    
    # Install kernel headers
    sudo yum install -y kernel-devel
    
    # Install additional tools
    sudo yum install -y git curl wget
}

# Function to install dependencies on Fedora
install_fedora() {
    print_status "Installing dependencies on Fedora..."
    
    # Install build tools
    sudo dnf groupinstall -y "Development Tools"
    sudo dnf install -y cmake pkg-config
    
    # Install LLVM/Clang
    sudo dnf install -y clang llvm llvm-devel
    
    # Install BPF dependencies
    sudo dnf install -y libbpf-devel elfutils-libelf-devel zlib-devel
    
    # Install kernel headers
    sudo dnf install -y kernel-devel
    
    # Install additional tools
    sudo dnf install -y git curl wget
}

# Function to install dependencies on Arch Linux
install_arch() {
    print_status "Installing dependencies on Arch Linux..."
    
    # Install build tools
    sudo pacman -S --noconfirm base-devel cmake pkg-config
    
    # Install LLVM/Clang
    sudo pacman -S --noconfirm clang llvm
    
    # Install BPF dependencies
    sudo pacman -S --noconfirm libbpf elfutils zlib
    
    # Install kernel headers
    sudo pacman -S --noconfirm linux-headers
    
    # Install additional tools
    sudo pacman -S --noconfirm git curl wget
}

# Function to install dependencies on macOS
install_macos() {
    print_warning "macOS is not supported for eBPF development"
    print_warning "This project requires Linux kernel features"
    exit 1
}

# Function to verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    local missing_deps=()
    
    # Check for required commands
    if ! command_exists clang; then
        missing_deps+=("clang")
    fi
    
    if ! command_exists llvm-strip; then
        missing_deps+=("llvm-strip")
    fi
    
    if ! command_exists pkg-config; then
        missing_deps+=("pkg-config")
    fi
    
    # Check for required libraries
    if ! pkg-config --exists libbpf; then
        missing_deps+=("libbpf")
    fi
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        print_success "All dependencies installed successfully!"
        return 0
    else
        print_error "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
}

# Function to check kernel version
check_kernel_version() {
    local kernel_version=$(uname -r | cut -d. -f1,2)
    local required_version="5.10"
    
    if [ "$(printf '%s\n' "$required_version" "$kernel_version" | sort -V | head -n1)" = "$required_version" ]; then
        print_success "Kernel version $(uname -r) is compatible"
    else
        print_warning "Kernel version $(uname -r) may not support all eBPF features"
        print_warning "Recommended: Linux kernel 5.10 or later"
    fi
}

# Main function
main() {
    print_status "Packet Anonymization Project - Dependency Installer"
    print_status "=================================================="
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_error "Please do not run this script as root"
        exit 1
    fi
    
    # Detect OS
    local os=$(detect_os)
    print_status "Detected OS: $os"
    
    # Install dependencies based on OS
    case $os in
        "debian")
            install_debian
            ;;
        "rhel")
            install_rhel
            ;;
        "fedora")
            install_fedora
            ;;
        "arch")
            install_arch
            ;;
        "macos")
            install_macos
            ;;
        *)
            print_error "Unsupported operating system: $os"
            exit 1
            ;;
    esac
    
    # Verify installation
    if verify_installation; then
        check_kernel_version
        print_success "Dependency installation completed successfully!"
        print_status "You can now build the project with: make build"
    else
        print_error "Dependency installation failed!"
        exit 1
    fi
}

# Run main function
main "$@"
