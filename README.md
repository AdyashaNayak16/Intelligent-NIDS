# Intelligent Network Intrusion Detection System (NIDS)

## Overview

This project is a real-time Network Intrusion Detection System built using Python and Scapy. The system captures live network traffic, analyzes packets across multiple OSI layers, and detects suspicious or malicious behavior using rule-based detection techniques.

The project currently supports detection of flooding attacks, ARP spoofing, DNS tunneling patterns, suspicious HTTP payloads, and beaconing activity. The architecture is modular so that new detectors and machine learning models can be integrated easily in future versions.

## Implemented Features

The IDS currently includes:

- Live packet sniffing and traffic analysis
- TCP, UDP, ICMP, and ARP packet inspection
- SYN flood detection
- UDP flood detection
- Port scan detection
- ARP spoof detection
- DNS tunneling heuristics
- HTTP payload inspection
- Beaconing traffic detection
- Structured alert logging

## Technologies Used

- Python
- Scapy
- Wireshark / Tshark
- Packet sniffing
- Behavioral traffic analysis

## Project Structure

```bash
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

## Current Development

The current version focuses on building the core IDS engine and behavioral detection framework. Future improvements will include machine learning-based anomaly detection, PCAP replay support, dashboard visualization, and threat intelligence integration.

## Learning Outcomes

This project explores concepts related to:

- TCP/IP and OSI networking
- Packet-level traffic analysis
- Intrusion detection systems
- Deep packet inspection
- Behavioral threat detection
- Modular cybersecurity engineering

