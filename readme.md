# Packet Anonymization Project - How To Make Guide

## 🎯 What This Project Does

This is a **real-time network packet anonymization tool** that uses eBPF/XDP (Extended Berkeley Packet Filter/Express Data Path) to anonymize network packets **before** they hit your disk. Think of it as a privacy shield for your network traffic!

### 🔍 Key Features:

- **Real-time anonymization** - Packets are anonymized on-the-fly
- **Configurable privacy** - You control what gets anonymized
- **Network protocol support** - Handles IPv4, ARP, and Ethernet headers
- **Prefix preservation** - Keeps network structure while hiding details

## 🏗️ Project Architecture (10-Year-Old Friendly)

### The Big Picture

Imagine you have a **mail sorting machine** that:

1. **Catches letters** (network packets) as they arrive
2. **Removes sensitive info** (anonymizes them)
3. **Sends them along** (drops them after processing)

### 🧩 Main Components

#### 1. **Kernel Program** (`prog_kern.c`)

- **What it does**: Lives inside the Linux kernel
- **Job**: Intercepts every network packet and anonymizes it
- **Think of it as**: A super-fast robot that works at the network level

#### 2. **Userspace Program** (`prog_userspace.c`)

- **What it does**: Runs in normal user space
- **Job**: Loads configuration and tells the kernel program what to anonymize
- **Think of it as**: The control panel for the robot

#### 3. **Configuration File** (`anonymization_config.txt`)

- **What it does**: Simple text file with settings
- **Job**: Tells the system what to anonymize
- **Think of it as**: The instruction manual

## 🔧 How It Works (Step by Step)

### Step 1: Packet Interception

```
Network Packet → Linux Kernel → eBPF Program (prog_kern.c)
```

### Step 2: Header Analysis

The program looks at different parts of the packet:

- **Ethernet header**: MAC addresses
- **IP header**: IP addresses
- **ARP header**: Address resolution info

### Step 3: Anonymization Process

For each field that needs anonymization:

1. **Extract** the original value
2. **Hash** it with a random salt
3. **Replace** with the hashed value
4. **Update** checksums if needed

### Step 4: Packet Handling

- **Drop the packet** (it's already been processed)
- **Configuration can be updated** without restarting

## 📁 File Structure Explained

```
packet-anonymization/
├── src/                          # Main source code
│   ├── prog_kern.c              # Kernel eBPF program
│   ├── prog_userspace.c         # Userspace control program
│   ├── common_structs.h         # Shared data structures
│   ├── anonymization_config.txt # Configuration file
│   └── Makefile                 # Build instructions
├── common/                      # Shared utilities
│   ├── common.mk               # Common build rules
│   ├── parsing_helpers.h       # Packet parsing utilities
│   └── rewrite_helpers.h       # Packet modification utilities
├── headers/                     # Linux kernel headers
├── libbpf/                     # BPF library (submodule)
└── README.md                   # Project documentation
```

## 🛠️ Building the Project

### Prerequisites

```bash
# Install required tools
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
sudo apt install linux-tools-$(uname -r)
sudo apt install linux-headers-$(uname -r)
```

### Build Steps

```bash
# 1. Clone and setup
git clone <repository-url>
cd packet-anonymization
git submodule init && git submodule update

# 2. Build the project
cd src
make

# 3. Install XDP tools
git clone https://github.com/xdp-project/xdp-tools.git
cd xdp-tools
git submodule init && git submodule update
./configure
make
```

## ⚙️ Configuration Options

The `anonymization_config.txt` file controls what gets anonymized:

```txt
# MAC Address Anonymization
anonymize_srcmac_oui: yes    # Anonymize first 3 bytes of source MAC
anonymize_srcmac_id: no      # Anonymize last 3 bytes of source MAC
anonymize_dstmac_oui: no     # Anonymize first 3 bytes of destination MAC
anonymize_dstmac_id: yes     # Anonymize last 3 bytes of destination MAC

# IP Address Anonymization
anonymize_srcipv4: 172.17.1.0/24, 127.0.0.1/1  # IP ranges to anonymize
anonymize_dstipv4: 172.17.1.0/24, 127.0.0.1/1

# Other Options
preserve_prefix: yes         # Keep network structure
anonymize_multicast_broadcast: no  # Handle broadcast packets
anonymize_mac_in_arphdr: yes       # Anonymize MAC in ARP
anonymize_ipv4_in_arphdr: yes      # Anonymize IP in ARP
```

## 🔍 Key Technical Concepts

### eBPF/XDP

- **eBPF**: Extended Berkeley Packet Filter - allows safe code execution in kernel
- **XDP**: Express Data Path - earliest possible packet interception point
- **Benefits**: High performance, safe, kernel-level processing

### Packet Anonymization Techniques

1. **Hashing**: Convert sensitive data to random-looking values
2. **Salt**: Add randomness to prevent reverse engineering
3. **Prefix Preservation**: Keep network structure while hiding details
4. **Checksum Updates**: Maintain packet integrity after modification

### Data Structures

```c
// Configuration structure
typedef struct anonymization_config {
    bool anonymize_multicast_broadcast;
    bool anonymize_srcmac_oui;
    bool anonymize_srcmac_id;
    bool anonymize_dstmac_oui;
    bool anonymize_dstmac_id;
    bool preserve_prefix;
    bool anonymize_mac_in_arphdr;
    bool anonymize_ipv4_in_arphdr;
    __u32 src_ip_mask_lengths;
    __u32 dest_ip_mask_lengths;
    __u32 random_salt;
} anonymization_config;
```

## 🎯 Use Cases

1. **Network Monitoring**: Capture traffic without privacy concerns
2. **Security Analysis**: Analyze patterns without exposing sensitive data
3. **Compliance**: Meet data protection requirements
4. **Research**: Share network data safely

## 🔧 Troubleshooting

### Common Issues:

1. **Permission denied**: Run with `sudo`
2. **Interface not found**: Check interface name with `ip link show`
3. **Build errors**: Ensure all dependencies are installed
4. **Kernel version**: Requires Linux 5.10+

### Debug Commands:

```bash
# Check loaded XDP programs
sudo ip link show <interface_name>

# View BPF maps
sudo bpftool map list

# Check kernel logs
dmesg | tail
```

## 🚀 Next Steps

1. **Customize configuration** for your network
2. **Add new protocols** (IPv6, TCP, UDP)
3. **Implement packet forwarding** instead of dropping
4. **Add statistics collection**
5. **Create web interface** for configuration

## 📚 Learning Resources

- [eBPF Documentation](https://ebpf.io/)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Linux Kernel Networking](https://www.oreilly.com/library/view/linux-kernel-networking/9781430261964/)

---

**Happy Packet Anonymizing! 🛡️🔒**
