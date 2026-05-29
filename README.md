Intelligent Network Intrusion Detection System (NIDS)

Overview

This project is a real-time Intelligent Network Intrusion Detection System (NIDS) built using Python and Scapy.

The system captures live network packets, analyzes protocol behavior across multiple OSI layers, and detects suspicious or malicious activities using rule-based behavioral analysis.

The project follows a modular cybersecurity architecture and is designed to be extended toward machine learning-based anomaly detection.



Features

Layer 2 Detection

 ARP Spoofing Detection

Layer 3 Detection

 IP Traffic Monitoring
 ICMP Activity Monitoring

Layer 4 Detection

 SYN Flood Detection
 UDP Flood Detection
 Port Scan Detection
 Time-window Behavioral Analysis

Layer 7 Detection

 DNS Tunneling Heuristics
 HTTP Payload Inspection
 Suspicious Payload Detection

Behavioral Analysis

 Beaconing Traffic Detection
 Stateful Packet Tracking
 Rate-based Detection



Technologies Used

 Python
 Scapy
 Wireshark / Tshark
 Packet Sniffing
 Behavioral Analysis
 Modular IDS Architecture



Project Structure

nids-project/
│
├── detectors/
│     ├── arp_detector.py
│     ├── beacon_detector.py
│     ├── dns_detector.py
│     ├── http_detector.py
│     ├── syn_detector.py
│     └── udp_detector.py
│
├── sniffer.py
├── logger.py
├── alerts.log
└── README.md



Current Detection Capabilities

Detection Type| Status
SYN Flood Detection| Implemented
UDP Flood Detection| Implemented
Port Scan Detection| Implemented
ARP Spoof Detection| Implemented
DNS Tunneling Detection| Implemented
HTTP Payload Analysis| Implemented
Beaconing Detection| Implemented



Logging System

The IDS generates structured security logs in:

alerts.log

Each log entry contains:

 Timestamp
 Alert Type
 Source Information



Future Improvements

 Machine Learning-based anomaly detection
 Isolation Forest integration
 Autoencoder-based traffic analysis
 LSTM packet sequence analysis
 Threat intelligence integration
 GeoIP enrichment
 Dashboard visualization
 PCAP replay support
 Suricata / Zeek integration



Learning Outcomes

This project helped in understanding:

 TCP/IP and OSI model
 Packet analysis
 Real-time intrusion detection
 Behavioral traffic analysis
 Deep Packet Inspection (DPI)
 Stateful detection systems
 Modular cybersecurity engineering