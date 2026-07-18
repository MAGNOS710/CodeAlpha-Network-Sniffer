# Basic Network Sniffer

A simple network packet sniffer built with Python and Scapy.

## Features

- Capture live network packets
- Display source and destination IP addresses
- Detect network protocols:
  - TCP
  - UDP
  - ICMP
  - IPv4
  - IPv6
  - ARP
- Display TCP/UDP ports
- Display packet payload when available
- Show packet size and timestamp

## Requirements

- Python 3.x
- Scapy

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run

```bash
python network_sniffer.py
```

Stop the sniffer using:

```text
Ctrl + C
```

## Technologies

- Python
- Scapy
