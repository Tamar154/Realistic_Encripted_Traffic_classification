# Realistic Encrypted network traffic classification based on Large Dataset

## Overview

This project focuses on identifying and classifying encrypted traffic by creating a unique dataset using a smart crawler and a feature extraction tool. The system generates and labels network traffic from various applications and network behaviors, particularly encrypted traffic. It then extracts meaningful features for use in machine learning models to improve the accuracy of traffic classification.

### Key Components:
- **Crawler**: Collects network traffic data and organizes PCAP files based on network conditions, application type, and traffic attribution.
- **Feature Extractor**: Processes PCAP files to extract network traffic features, such as packet sizes, TLS records, inter-arrival times, and ASN-related information.

---

## Files

### `crawler.py`
The web crawler simulates different operations such as downloading, uploading, browsing, playing video streams, and real-time communication. It captures network traffic during these operations under various network conditions.

#### Features:
- **Traffic Capturing**: Captures traffic while interacting with websites or downloading content.
- **Network Condition Simulation**: Applies conditions like delay, packet loss, or bandwidth throttling.
- **PCAP Organization**: Captures are saved and organized by application, network conditions, and attribution.

#### Usage:
```bash
python crawler.py
```

- `operation`: Choose between 'download', 'browse', 'video', 'upload', or 'meeting'.
- `max_links`: Set the maximum number of URLs to crawl.

### `feature_extractor.py`
This script extracts various features from PCAP files to facilitate machine learning-based classification. It extracts features like packet sizes, TLS records, inter-arrival times, clumps, and ASN details. Additionally, DNS and payload byte distribution features are calculated.

#### Features:
- **Packet-Level Features**: Min, max, and mean packet sizes, small packet ratio, and inter-arrival times.
- **TLS Features**: Min, max, and mean TLS record sizes and count of outgoing/incoming TLS records.
- **Payload Byte Distribution**: Frequency distribution of raw bytes in payloads.
- **DNS Features**: Extracts domain name lengths and TTL values from DNS responses.
- **ASN Features**: Extracts ASN-related information from IP addresses.

#### Usage:
```bash
python feature_extractor.py
```
- Input: PCAP files to extract features from.
- Output: CSV file with extracted features for machine learning.

---

## Setup and Installation

### Prerequisites:
- Python 3.7+
- Required Python libraries:
  - `pandas`
  - `numpy`
  - `scapy`
  - `pyshark`
  - `selenium`
  - `geoip2`

Install the required libraries using:
```bash
pip install -r requirements.txt
```

### Setting Up GeoLite2 ASN Database
This project requires the GeoLite2 ASN database to extract ASN features. Download it from [MaxMind GeoLite2 ASN](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place the `GeoLite2-ASN.mmdb` file in the project directory.
