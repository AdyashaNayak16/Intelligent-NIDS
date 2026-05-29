# Intelligent Network Intrusion Detection System (NIDS)

## Overview

An intelligent real-time Network Intrusion Detection System built using Python and Scapy.

The system captures and analyzes live network traffic across multiple OSI layers to detect suspicious activity such as flooding attacks, ARP spoofing, DNS tunneling patterns, malicious HTTP payloads, and beaconing behavior.

The project follows a modular architecture to support future integration of machine learning-based anomaly detection.

---

## Implemented Features

### Network Monitoring
- Live packet sniffing
- TCP, UDP, ICMP, and ARP analysis
- Stateful traffic tracking
- Real-time packet inspection

### Detection Modules
- SYN Flood Detection
- UDP Flood Detection
- Port Scan Detection
- ARP Spoof Detection
- DNS Tunneling Heuristics
- HTTP Payload Inspection
- Beaconing Detection

### Logging
- Structured alert logging
- Timestamped security events
- Persistent alert storage

---

## Technologies Used

- Python
- Scapy
- Wireshark / Tshark
- Packet Sniffing
- Behavioral Traffic Analysis

---

## Project Structure


INTELLIGENT-NIDS/
│
├── detectors/
│   ├── arp_detector.py
│   ├── beacon_detector.py
│   ├── dns_detector.py
│   ├── http_detector.py
│   ├── syn_detector.py
│   └── udp_detector.py
│
├── sniffer.py
├── logger.py
├── alerts.log
└── README.md
```

---

## Current Status

The current implementation includes:
- modular detector architecture
- real-time traffic inspection
- behavioral analysis modules
- application-layer payload inspection

Future development will focus on:
- machine learning integration
- anomaly detection models
- PCAP replay support
- dashboard visualization
- threat intelligence integration

---

## Learning Outcomes

This project explores:
- TCP/IP and OSI networking
- packet-level traffic analysis
- intrusion detection concepts
- deep packet inspection
- behavioral threat detection
- modular cybersecurity engineering

---

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes only.