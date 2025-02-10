# SIMPLE-IDS-ON-LINUX-NETWORK-NAMESPACES

## Introduction
This project implements a **Simple Intrusion Detection System (IDS)** using **Python** and **Linux network namespaces**. The IDS monitors network traffic within a namespace to detect suspicious activity.

## Features
- Creates and manages Linux network namespaces.
- Captures network traffic inside a namespace.
- Analyzes packets for potential intrusions based on predefined rules.
- Logs and alerts when suspicious activity is detected.

## Requirements
Ensure you have the following installed:
- Linux OS (Ubuntu, Debian, etc.)
- Python 3.x
- `iproute2` package for namespace management (`ip netns` command)
- `scapy` Python library for packet sniffing

To install dependencies, run:
```bash
sudo apt update && sudo apt install iproute2
pip install scapy
```

## Usage
### 1. Create a Network Namespace
Run the following command to create a network namespace:
```bash
sudo ip netns add test_ns
```

### 2. Run the IDS Script
Start the IDS within the namespace:
```bash
sudo python3 ids.py test_ns
```

### 3. Generate Test Traffic
In another terminal, run:
```bash
sudo ip netns exec test_ns ping -c 4 8.8.8.8
```
The IDS will capture and analyze packets.

### 4. Delete the Namespace (Cleanup)
After testing, delete the namespace:
```bash
sudo ip netns del test_ns
```

## How It Works
1. The script creates or connects to a network namespace.
2. It uses **Scapy** to sniff network packets.
3. Packets are checked against basic intrusion rules (e.g., detecting pings, SYN floods).
4. Suspicious packets are logged and reported.

## Example Output
```
[INFO] Monitoring network traffic inside namespace: test_ns
[ALERT] ICMP packet detected! Possible ping flood attack.
[ALERT] Suspicious SYN packet detected! Possible SYN flood attack.
```

## Future Improvements
- Add machine learning for anomaly detection.
- Implement logging to a database.
- Integrate with SIEM tools for real-time monitoring.

## Author
Merita Odera @this_barbie_is_an_engineer

## License
MIT License

