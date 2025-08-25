# Installation Guide - Packet Anonymization Project

This guide will help you install and set up the Packet Anonymization Project on your Linux system.

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+, Fedora 34+)
- **Kernel Version**: Linux 5.10 or later (required for eBPF/XDP features)
- **Architecture**: x86_64 (AMD64)
- **Memory**: At least 2GB RAM
- **Storage**: 1GB free space

### Required Dependencies

- **Build Tools**: gcc, make, cmake, pkg-config
- **LLVM/Clang**: clang, llvm-strip (for eBPF compilation)
- **BPF Libraries**: libbpf-dev, libelf-dev, zlib1g-dev
- **Kernel Headers**: linux-headers-$(uname -r)
- **Additional Tools**: git, curl, wget

## Quick Installation

### Option 1: Automated Installation (Recommended)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Bhup-GitHUB/anoymaization
   cd packet-anonymization
   ```

2. **Run the automated installer**:
   ```bash
   ./scripts/install_dependencies.sh
   ```

3. **Build the project**:
   ```bash
   cd src
   make build
   ```

### Option 2: Manual Installation

#### Step 1: Install Dependencies

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config clang llvm llvm-dev
sudo apt install -y libbpf-dev libelf-dev zlib1g-dev
sudo apt install -y linux-headers-$(uname -r) git curl wget
```

**RHEL/CentOS**:
```bash
sudo yum install -y epel-release
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake pkg-config clang llvm llvm-devel
sudo yum install -y libbpf-devel elfutils-libelf-devel zlib-devel
sudo yum install -y kernel-devel git curl wget
```

**Fedora**:
```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y cmake pkg-config clang llvm llvm-devel
sudo dnf install -y libbpf-devel elfutils-libelf-devel zlib-devel
sudo dnf install -y kernel-devel git curl wget
```

**Arch Linux**:
```bash
sudo pacman -S --noconfirm base-devel cmake pkg-config clang llvm
sudo pacman -S --noconfirm libbpf elfutils zlib linux-headers git curl wget
```

#### Step 2: Clone and Build

```bash
git clone https://github.com/yourusername/packet-anonymization.git
cd packet-anonymization/src
make build
```

## Verification

### Check Dependencies

Verify that all dependencies are installed correctly:

```bash
cd src
make check-deps
```

### Test Build

Test the compilation process:

```bash
cd src
make test-build
```

### Check Kernel Compatibility

Verify your kernel supports eBPF/XDP:

```bash
uname -r  # Should be 5.10 or later
```

## Configuration

### Create Configuration File

Copy the example configuration:

```bash
cp src/anonymization_config.txt my_config.txt
```

Edit the configuration file to match your requirements:

```bash
nano my_config.txt
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `anonymize_srcmac_oui` | Anonymize source MAC OUI | yes |
| `anonymize_srcmac_id` | Anonymize source MAC ID | no |
| `anonymize_dstmac_oui` | Anonymize destination MAC OUI | no |
| `anonymize_dstmac_id` | Anonymize destination MAC ID | yes |
| `preserve_prefix` | Preserve network structure | yes |
| `anonymize_multicast_broadcast` | Handle broadcast packets | no |
| `random_salt` | Hash salt value | 0x12345678 |

## Usage

### Basic Usage

1. **Start the anonymization service**:
   ```bash
   sudo ./build/prog_userspace <interface> <config_file>
   ```

   Example:
   ```bash
   sudo ./build/prog_userspace eth0 my_config.txt
   ```

2. **Monitor statistics**:
   The program will display statistics every 5 seconds.

3. **Stop the service**:
   Press `Ctrl+C` to gracefully stop the service.

### Advanced Usage

#### Multiple Interfaces

To anonymize traffic on multiple interfaces, run separate instances:

```bash
# Terminal 1
sudo ./build/prog_userspace eth0 config1.txt

# Terminal 2
sudo ./build/prog_userspace eth1 config2.txt
```

#### Custom Configuration

Create different configurations for different use cases:

```bash
# High privacy configuration
cp src/anonymization_config.txt high_privacy.txt
# Edit high_privacy.txt to anonymize everything

# Network analysis configuration
cp src/anonymization_config.txt network_analysis.txt
# Edit network_analysis.txt to preserve structure
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied
```bash
Error: Permission denied
```
**Solution**: Run with `sudo` privileges.

#### 2. Interface Not Found
```bash
Error: Interface eth0 not found
```
**Solution**: Check available interfaces:
```bash
ip link show
```

#### 3. BPF Program Load Failed
```bash
Error: Failed to load BPF object
```
**Solution**: Check kernel version and BPF support:
```bash
uname -r
cat /proc/version
```

#### 4. Missing Dependencies
```bash
Error: libbpf not found
```
**Solution**: Install missing dependencies:
```bash
sudo apt install libbpf-dev  # Ubuntu/Debian
sudo yum install libbpf-devel  # RHEL/CentOS
```

#### 5. Kernel Headers Missing
```bash
Error: linux/bpf.h not found
```
**Solution**: Install kernel headers:
```bash
sudo apt install linux-headers-$(uname -r)  # Ubuntu/Debian
sudo yum install kernel-devel  # RHEL/CentOS
```

### Debug Mode

Build with debug information:

```bash
cd src
make debug
```

### Logs and Monitoring

Check system logs for errors:

```bash
dmesg | tail
journalctl -f
```

## Uninstallation

### Remove Installed Files

```bash
cd src
sudo make uninstall
```

### Remove Dependencies (Optional)

**Ubuntu/Debian**:
```bash
sudo apt remove clang llvm llvm-dev libbpf-dev libelf-dev zlib1g-dev
```

**RHEL/CentOS**:
```bash
sudo yum remove clang llvm llvm-devel libbpf-devel elfutils-libelf-devel zlib-devel
```

## Support

### Getting Help

1. **Check the documentation**: Read the README.md file
2. **Review logs**: Check system logs for error messages
3. **Verify configuration**: Ensure your config file is valid
4. **Test with minimal config**: Start with default settings

### Reporting Issues

When reporting issues, please include:

- Operating system and version
- Kernel version (`uname -r`)
- Error messages and logs
- Configuration file contents
- Steps to reproduce the issue

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on contributing to the project.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.
