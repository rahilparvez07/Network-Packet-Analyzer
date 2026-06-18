from scapy.all import *

def analyze(packet):

    if IP in packet:

        print("--------------------------------")

        print("Source IP:", packet[IP].src)

        print("Destination IP:", packet[IP].dst)

        if packet.haslayer(TCP):
            protocol = "TCP"

        elif packet.haslayer(UDP):
            protocol = "UDP"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        else:
            protocol = "Other"

        print("Protocol:", protocol)

        print("Packet Size:", len(packet), "Bytes")

        print("--------------------------------")

sniff(prn=analyze,timeout=10)
