# SYN Scanner - Asynchronous TCP SYN Port Scanner IN GO | [简体中文](https://github.com/chuanjiesun/syn_scan/blob/main/README_cn.md)

*This code was created in 2019 while learning zmap network scanning techniques.*

A high-performance asynchronous TCP SYN port scanner written in Go, capable of scanning single IPs or CIDR ranges with rate limiting and concurrent processing.

## Features

- **Asynchronous SYN Scanning**: Uses raw TCP SYN packets for fast port detection
- **CIDR Support**: Scan single IPs or entire network ranges (e.g., 192.168.1.0/24)
- **Rate Limiting**: Built-in rate limiting to prevent network congestion
- **Concurrent Processing**: Multi-threaded packet sending and receiving
- **Duplicate Prevention**: Uses sync.Map and FNV hashing to prevent duplicate results
- **Cross-Platform**: Supports both Windows and Linux with appropriate pcap libraries
- **Result Export**: Saves scan results to timestamped CSV files

## Dependencies

This scanner uses the following Go libraries:

### Core Libraries
- `github.com/google/gopacket` - Network packet processing
- `github.com/google/gopacket/layers` - Network protocol layer definitions
- `github.com/google/gopacket/pcap` - Packet capture functionality
- `golang.org/x/time/rate` - Rate limiting for packet transmission
- `github.com/libp2p/go-netroute` - Network routing information

### System Requirements

#### Windows
**Required**: Npcap version 1.72 (based on libpcap version 1.10.2-PRE-GIT)
- Download from: https://npcap.com/#download
- Npcap is the Windows packet capture library from the Nmap project
- Provides WinPcap compatibility with enhanced security and performance
- Supports Windows 7 and later versions

#### Linux
**Required**: libpcap library
- Download from: https://www.tcpdump.org/
- Install via package manager:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install libpcap-dev
  
  # CentOS/RHEL
  sudo yum install libpcap-devel
  
  # Arch Linux
  sudo pacman -S libpcap
  ```

## Installation

1. **Install Go dependencies**:
   ```bash
   go mod tidy
   ```

2. **Install platform-specific pcap library** (see System Requirements above)

3. **Build the scanner**:
   ```bash
   go build -o syn_scanner syn_scan.go
   ```

## Usage

### Basic Syntax
```bash
./syn_scanner -ip <target_ip> -port <target_port> [-rate <packets_per_second>]
```

### Parameters
- `-ip`: Target IP address or CIDR range (required)
  - Single IP: `192.168.1.100`
  - CIDR range: `192.168.1.0/24`
  - Multiple IPs: `192.168.1.1,192.168.1.2,10.0.0.0/16`
- `-port`: Target port number (required)
- `-rate`: Packet transmission rate (optional, default: 100 packets/second)

### Examples

**Scan single IP**:
```bash
./syn_scanner -ip 192.168.1.100 -port 80
```

**Scan CIDR range**:
```bash
./syn_scanner -ip 192.168.1.0/24 -port 22
```

**Scan with custom rate**:
```bash
./syn_scanner -ip 10.0.0.0/16 -port 443 -rate 500
```

**Scan multiple targets**:
```bash
./syn_scanner -ip "192.168.1.1,10.0.0.0/24" -port 3389
```

## SYN Scanning Process

The scanner implements an asynchronous TCP SYN scanning workflow:

### 1. Initialization Phase
- Parse command-line arguments and validate inputs
- Resolve IP addresses from CIDR notation if needed
- Shuffle target IP list to avoid firewall pattern detection
- Obtain network interface information (MAC addresses, gateway)
- Initialize pcap handle for packet capture
- Create rate limiter and random seed for sequence numbers

### 2. Scanning Phase
- **Concurrent Architecture**: 
  - Sender goroutine: Constructs and sends SYN packets
  - Receiver goroutine: Captures and processes SYN+ACK responses
- **Packet Construction**:
  - Ethernet layer with source/destination MAC addresses
  - IPv4 layer with source/destination IP addresses
  - TCP layer with SYN flag and unique sequence numbers
- **Rate Limiting**: Uses token bucket algorithm to control transmission speed
- **Sequence Number Validation**: Uses Murmur3 hash with random seed for packet verification

### 3. Response Processing
- **Packet Filtering**: Only processes TCP packets with SYN+ACK flags
- **Sequence Validation**: Verifies response sequence numbers match sent packets
- **Duplicate Prevention**: 
  - Uses sync.Map for thread-safe storage
  - Implements FNV hashing to prevent duplicate IP:Port combinations
- **Result Recording**: Saves open ports to timestamped CSV files

### 4. Key Algorithms
- **Murmur3 Hashing**: Generates unique sequence numbers for packet verification
- **FNV Hashing**: Creates fingerprints for IP:Port combinations to prevent duplicates
- **Token Bucket Rate Limiting**: Ensures controlled packet transmission rates
- **Concurrent Map Operations**: Thread-safe result storage using sync.Map

## Output

Scan results are saved to CSV files with the format:
- Filename: `scan_result_YYYY-MM-DD-HH-MM-SS.csv`
- Content: IP address and port number of discovered open ports
- Console output includes scan statistics and timing information

## Performance Considerations

- **Memory Usage**: Efficient packet processing with minimal memory allocation
- **CPU Usage**: Multi-core utilization through goroutines
- **Network Impact**: Rate limiting prevents network congestion
- **Scalability**: Can handle large CIDR ranges with appropriate rate settings

## Security Notes

- **Administrator Privileges**: Requires elevated privileges for raw packet access
- **Firewall Considerations**: May trigger security alerts on target networks
- **Rate Limiting**: Use appropriate rates to avoid being blocked by firewalls
- **Legal Compliance**: Only scan networks you own or have explicit permission to test

## Troubleshooting

### Common Issues
1. **Permission Denied**: Run with administrator/root privileges
2. **No Network Interface**: Ensure pcap library is properly installed
3. **High CPU Usage**: Reduce the `-rate` parameter
4. **No Results**: Check firewall settings and network connectivity

### Debug Information
- Scanner displays libpcap version information on startup
- Network interface details are logged during initialization
- Scan statistics are provided upon completion

## License

This project is provided as-is for educational and authorized security testing purposes.
