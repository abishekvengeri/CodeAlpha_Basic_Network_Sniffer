# Basic Network Sniffer using Python

## CodeAlpha Internship Project

This project implements a **basic network packet sniffer** using **Python and Scapy**.  
The sniffer captures live network traffic, analyzes packet structure, identifies protocols, and displays useful information such as source and destination IP addresses, protocol type, and payload data.

---

## Objectives

- Capture live network traffic packets
- Analyze packet structure and protocol layers
- Understand how data flows through a network
- Identify common protocols such as TCP, UDP, and ICMP
- Display meaningful packet information

---

## Tools & Technologies

- Python 3
- Scapy
- Kali Linux
- Git & GitHub

---

## Project Structure

```
CodeAlpha_Basic_Network_Sniffer/
├── README.md
├── scripts/
│   └── sniffer.py
└── screenshots/
```

---

## Implementation Overview

### Packet Capturing
- Uses Scapy’s `sniff()` function to capture packets in real time.
- Requires root privileges to access network interfaces.

### Packet Analysis
For each captured packet, the program extracts:
- Source IP address
- Destination IP address
- Protocol type (TCP / UDP / ICMP)
- Payload data (first 50 bytes, if available)

### Protocol Identification
- **TCP** – Reliable, connection-oriented communication
- **UDP** – Fast, connectionless communication
- **ICMP** – Network diagnostics (e.g., ping)

---

## How to Run

### Install dependency
```bash
sudo apt install python3-scapy
```

### Run the sniffer
```bash
sudo python3 scripts/sniffer.py
```

### Generate test traffic (new terminal)
```bash
ping -c 3 8.8.8.8
curl http://example.com
```

Stop the sniffer using `CTRL + C`.

---

## Output

The sniffer displays:
- Source IP
- Destination IP
- Protocol
- Payload (if present)

This output helps understand how data packets are structured and transmitted across a network.

---

## Learning Outcome

- Practical understanding of packet sniffing
- Hands-on experience with network protocols
- Familiarity with Scapy for packet analysis
- Better understanding of network data flow

---

## Author

Abishek  
CodeAlpha Internship Project
