# cybersecurity-automation-tool
Automate data extraction from pcap (packet capture) files.

# Description
This tool is designed to automate the process of capturing and analyzing network traffic using pcap files. It utilizes PyShark to read, filter, and analyze network packets, providing insights into network activities.

# Installation
To use this tool, you need to have Python installed on your system along with PyShark. You can install PyShark using pip: install PyShark

# Usage
To run the tool, execute the script with Python. Ensure you have a pcap file named '' in the same directory or modify the script to point to your pcap file.

# Basic Commands
- To start capturing packets: `cap = pyshark.FileCapture('your_pcap_file.pcapng')`
- To filter packets: `filtered = filter_packets(cap, ip='')`
- To analyze packets: `analysis = analyze_packet(filtered)`

# Features
- **Packet Capture**: Captures packets from pcap files.
- **Packet Filtering**: Filters packets based on IP, protocol, or port.
- **Data Analysis**: Analyzes the captured packets to count occurrences of each protocol.

# Contributing
Contributions to this project are welcome. Please fork the repository and submit a pull request with your changes.