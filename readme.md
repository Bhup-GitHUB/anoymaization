# 🔒 Packet Anonymization Project

A high-performance **eBPF/XDP-based packet anonymization tool** for network traffic analysis and privacy protection. This project provides real-time packet anonymization at the kernel level with configurable privacy settings.

## ✨ Features

- **🚀 High Performance**: eBPF/XDP implementation for minimal latency
- **🔧 Configurable**: Granular control over MAC and IP address anonymization
- **🛡️ Privacy Preserving**: Hash-based anonymization with salt support
- **🌐 Network Structure Preservation**: Optional prefix preservation for analysis
- **📊 Real-time Statistics**: Live monitoring of anonymization metrics
- **🔍 ARP Support**: Complete ARP packet anonymization
- **⚙️ Easy Configuration**: Simple text-based configuration file

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Userspace     │    │   eBPF Kernel   │    │   Network       │
│   Control       │◄──►│   Program       │◄──►│   Interface     │
│   Program       │    │   (XDP)         │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Linux kernel 5.10+
- clang/llvm
- libbpf-dev
- Root privileges

### Installation

```bash
# Clone the repository
git clone https://github.com/Bhup-GitHUB/anoymaization.git
cd anoymaization

# Install dependencies
./scripts/install_dependencies.sh

# Build the project
cd src
make build
```

### Usage

```bash
# Run with default configuration
sudo ./prog_userspace eth0 anonymization_config.txt

# Monitor statistics (Ctrl+C to stop)
=== Packet Anonymization Statistics ===
Packets processed:     1,234,567
Packets anonymized:    987,654
MAC addresses anonymized: 456,789
IP addresses anonymized:  789,012
ARP packets anonymized:   12,345
Errors:               0
=====================================
```

## ⚙️ Configuration

Edit `src/anonymization_config.txt` to customize anonymization behavior:

```ini
# MAC Address Anonymization
anonymize_srcmac_oui: yes    # Anonymize source MAC OUI
anonymize_srcmac_id: no      # Keep source MAC NIC ID
anonymize_dstmac_oui: no     # Keep destination MAC OUI
anonymize_dstmac_id: yes     # Anonymize destination MAC NIC ID

# IP Address Anonymization
anonymize_srcipv4: yes       # Anonymize source IPv4
anonymize_dstipv4: yes       # Anonymize destination IPv4

# Network Structure
preserve_prefix: yes         # Preserve network structure
random_salt: 0x12345678      # Hash salt for consistency
```

## 🎯 Use Cases

- **Network Analysis**: Preserve network structure while protecting privacy
- **Security Research**: Anonymize traffic for malware analysis
- **Compliance**: Meet data protection requirements
- **Development**: Test applications with anonymized data

## 📁 Project Structure

```
anoymaization/
├── src/                    # Source code
│   ├── prog_kern.c        # eBPF kernel program
│   ├── prog_userspace.c   # Userspace control program
│   ├── common_structs.h   # Shared data structures
│   └── anonymization_config.txt
├── common/                 # Common utilities
├── docs/                   # Documentation
├── scripts/               # Build and installation scripts
└── .github/               # GitHub templates and workflows
```

## 🔧 Development

```bash
# Build with debug symbols
make debug

# Build for production
make release

# Check dependencies
make check-deps

# Clean build artifacts
make clean
```



## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📚 Documentation

- [Installation Guide](docs/INSTALL.md) - Detailed installation instructions
- [Configuration Reference](src/anonymization_config.txt) - Configuration options
- [API Documentation](common/) - Helper functions and utilities

---

**⚠️ Warning**: This tool modifies network packets at the kernel level. Use with caution and ensure you have proper authorization for network monitoring activities.
