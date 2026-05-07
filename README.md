# Simple-TCP-IP-PacketSniffer-Tool
a lightweight network traffic monitoring tool built with Python and Scapy. It captures TCP packets on a specified network interface in real-time, logging connection details to both console and a timestamped log file.
Features

    Real-time TCP packet capture - Monitors live network traffic on any available interface

    Connection logging - Records source/destination IP addresses and port numbers for each TCP connection

    Dual output - Displays connections in console while simultaneously writing to a log file

    Log file persistence - Automatically saves captured data with interface-specific filenames (e.g., sniffer_eth0_log.txt)

    Cross-platform - Works on Linux, macOS, and Windows (with appropriate permissions)

Use Cases

    Network troubleshooting and debugging

    Understanding application network behavior

    Security monitoring and analysis

    Educational purposes for learning TCP/IP protocols

Requirements

    Python 3.x

    Scapy library (pip install scapy)

    Administrative/root privileges (required for packet capture)



Basic Syntax
python packetsniff.py <interface>

# Linux (requires sudo)
sudo python packetsniff.py eth0

# macOS
sudo python packetsniff.py en0

# Windows (as Administrator)
python packetsniff.py "Ethernet"
