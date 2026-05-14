from scapy.all import sniff
from datetime import datetime

packet_count = 0

def process_packet(packet):
    global packet_count
    packet_count += 1

    print("\n==============================")
    print(f"Packet No: {packet_count}")
    print(f"Time: {datetime.now().strftime('%H:%M:%S')}")

    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")

    if packet.haslayer("TCP"):
        print("Protocol       : TCP")

    elif packet.haslayer("UDP"):
        print("Protocol       : UDP")

    elif packet.haslayer("ICMP"):
        print("Protocol       : ICMP")

    print("==============================")

def start_sniffer():
    print("🚀 Advanced Sniffer Started... Press Ctrl+C to stop\n")
    sniff(filter="tcp", prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffer()