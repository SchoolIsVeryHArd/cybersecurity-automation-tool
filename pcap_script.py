#using pyshark to capture packets
import pyshark

cap = pyshark.FileCapture('pcap.pcapng')

# filtering packets based on IP, protocol, and port

def filter_packets(capture, ip=None, protocol=None, port=None):
    """
    Filter packets based on IP, protocol, and port.

    Parameters:
    capture: The capture file to filter through.
    ip (str, optional): IP address to filter by.
    protocol (str, optional): Protocol to filter by.
    port (str, optional): Port number to filter by.

    Returns:
    list: A list of filtered packets.
    """
    filtered_packets = []
    for packet in capture:
        if ip and hasattr(packet, 'ip') and (packet.ip.src == ip or packet.ip.dst == ip):
            filtered_packets.append(packet)
        elif protocol and hasattr(packet, protocol.lower()):
            filtered_packets.append(packet)
        elif port and hasattr(packet, 'tcp') and (packet.tcp.srcport == port or packet.tcp.dstport == port):
            filtered_packets.append(packet)
    return filtered_packets


#Data analysis of captured packets
def analyze_packet(packet):
    """
    Analyze the given packets to count occurrences of each protocol.

    Parameters:
    packets (list): A list of packet objects to analyze.

    Returns:
    dict: A dictionary with protocol types as keys and counts as values.
    """
    proocol_count = {}
    for packet in packet:
        if hasattr(packet, 'ip'):
            protocol = packet.ip.proto
            proocol_count[protocol] = proocol_count.get(protocol, 0) 
            return proocol_count
        
# Printing packet details
for packet in cap:
    print(packet)
for packet in cap:
    if 'IP' in packet:
        print(f"source IP: {packet.ip.src}")
        print(f"destination IP: {packet.ip.dst}")

filtered = filter_packets(cap, ip='192.168.1.6')
analysis = analyze_packet(filtered)
print(analysis)
# Closing the capture file
cap.close()

#exception handling

try:
    cap = pyshark.FileCapture('pcap.pcapng')
except Exception as e:
    print(f"Error: {e}")

cap.close()



