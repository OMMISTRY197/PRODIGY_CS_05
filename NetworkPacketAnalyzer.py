from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Identify the protocol
        if TCP in packet:
            protocol_name = 'TCP'
            payload = packet[TCP].payload
        elif UDP in packet:
            protocol_name = 'UDP'
            payload = packet[UDP].payload
        else:
            protocol_name = 'Other'
            payload = packet[IP].payload

        # Display packet information
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol_name}")
        print(f"Payload: {payload}\n")

def start_sniffing(interface):
    conf.iface = interface  # Set the interface for Scapy
    print(f"Starting packet sniffing on interface {interface}...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # Replace 'Wi-Fi' with the appropriate network interface name for your Wi-Fi adapter
    interface = 'Wi-Fi'
    start_sniffing(interface)
