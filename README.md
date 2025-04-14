# Uzdechka - Network Protocol Analyzer

A lightweight, powerful network protocol analyzer and packet sniffer for real-time traffic inspection, protocol analysis, and network monitoring.

## Features

- Real-time packet capture and protocol analysis
- Support for multiple protocols (TCP, UDP, ICMP, HTTP, DNS, SMTP)
- Deep packet inspection with protocol-specific analysis
- Advanced protocol fingerprinting for ambiguous traffic
- Traffic pattern detection and anomaly alerts
- Interactive dashboard with live visualization
- Connection tracking and bandwidth monitoring

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/uzdechka.git
cd uzdechka

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Packet Capture
```bash
# Capture packets from interface
python -m examples.basic_capture -i eth0 -c 100

# Read packets from file
python -m examples.basic_capture -f capture.pcap --filter "tcp"
```

### Advanced Protocol Analysis
```bash
# Analyze specific protocol in detail
python -m examples.protocol_analysis -i eth0 --protocol http

# Analyze packets with deep inspection
python -m examples.protocol_analysis -f capture.pcap -c 50
```

### Live Network Monitoring
```bash
# Monitor network traffic in real-time
python -m examples.live_monitoring -i eth0 --refresh-interval 0.5

# Monitor with custom alert threshold
python -m examples.live_monitoring -i eth0 --alert-threshold 3
```

## Requirements

- Python 3.9+
- scapy >= 2.6.1
- rich >= 14.0.0
- Administrator/root privileges (required for raw packet capture)
- Windows, macOS, or Linux operating system

## License

MIT License

## Disclaimer

This tool is intended for network administration, educational purposes, and authorized network analysis only. Always ensure you have proper authorization before analyzing network traffic.
