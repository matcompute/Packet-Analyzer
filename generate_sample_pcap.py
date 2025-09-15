#!/usr/bin/env python3
"""
Generate a sample PCAP file for testing
"""
from scapy.all import *
import random

def create_sample_pcap():
    """Create a sample PCAP file with various packet types"""
    packets = []
    
    # Create some IP packets
    for i in range(10):
        ip_pkt = IP(src="192.168.1." + str(random.randint(1, 50)), dst="8.8.8.8")
        tcp_pkt = TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        packets.append(ip_pkt/tcp_pkt)
    
    # Create some DNS packets
    for i in range(5):
        dns_pkt = DNS(rd=1, qd=DNSQR(qname="example.com"))
        udp_pkt = UDP(sport=random.randint(1024, 65535), dport=53)
        ip_pkt = IP(src="192.168.1." + str(random.randint(1, 50)), dst="8.8.8.8")
        packets.append(ip_pkt/udp_pkt/dns_pkt)
    
    # Create some ICMP packets
    for i in range(5):
        icmp_pkt = ICMP(type=8, code=0)  # Echo request
        ip_pkt = IP(src="192.168.1." + str(random.randint(1, 50)), dst="8.8.8.8")
        packets.append(ip_pkt/icmp_pkt)
    
    # Write to file
    wrpcap("sample_data/sample.pcap", packets)
    print("Created sample.pcap with", len(packets), "packets")

if __name__ == "__main__":
    create_sample_pcap()