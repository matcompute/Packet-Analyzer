#!/usr/bin/env python3
"""
Packet Analyzer and Anomaly Detection Tool
A simplified Wireshark-like tool for network analysis
"""

import scapy.all as scapy
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
import argparse
import logging
import os
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.anomalies = []
        self.protocol_stats = {}
        
    def capture_packets(self, count=100, interface=None, timeout=30):
        """Capture network packets"""
        logger.info(f"Capturing {count} packets...")
        try:
            if interface:
                self.packets = scapy.sniff(count=count, iface=interface, timeout=timeout)
            else:
                self.packets = scapy.sniff(count=count, timeout=timeout)
            logger.info(f"Captured {len(self.packets)} packets")
            return True
        except Exception as e:
            logger.error(f"Error capturing packets: {e}")
            return False
            
    def read_pcap(self, file_path):
        """Read packets from a pcap file"""
        try:
            if os.path.exists(file_path):
                self.packets = scapy.rdpcap(file_path)
                logger.info(f"Read {len(self.packets)} packets from {file_path}")
                return True
            else:
                logger.error(f"File {file_path} does not exist")
                return False
        except Exception as e:
            logger.error(f"Error reading pcap file: {e}")
            return False
            
    def analyze_packets(self):
        """Analyze captured packets for anomalies"""
        if not self.packets:
            logger.warning("No packets to analyze")
            return
            
        logger.info("Analyzing packets...")
        
        # Reset stats
        self.anomalies = []
        self.protocol_stats = Counter()
        
        # Protocol distribution
        for packet in self.packets:
            if packet.haslayer(scapy.IP):
                self.protocol_stats[packet[scapy.IP].proto] += 1
                
                # Check for DNS anomalies
                if packet.haslayer(scapy.DNS):
                    self._check_dns_anomalies(packet)
                    
                # Check for TCP anomalies
                if packet.haslayer(scapy.TCP):
                    self._check_tcp_anomalies(packet)
                    
                # Check for ICMP anomalies
                if packet.haslayer(scapy.ICMP):
                    self._check_icmp_anomalies(packet)
                    
        logger.info("Analysis complete")
        
    def _check_dns_anomalies(self, packet):
        """Check for DNS-related issues"""
        dns = packet[scapy.DNS]
        
        # Check for DNS response with no answers
        if dns.qr == 1 and dns.ancount == 0:
            self.anomalies.append({
                'type': 'DNS',
                'description': 'DNS response with no answers',
                'src_ip': packet[scapy.IP].src,
                'dst_ip': packet[scapy.IP].dst
            })
            
        # Check for oversized DNS packets
        if len(packet) > 512:  # DNS typically uses 512 bytes for UDP
            self.anomalies.append({
                'type': 'DNS',
                'description': 'Oversized DNS packet',
                'src_ip': packet[scapy.IP].src,
                'dst_ip': packet[scapy.IP].dst,
                'size': len(packet)
            })
            
    def _check_tcp_anomalies(self, packet):
        """Check for TCP-related issues"""
        tcp = packet[scapy.TCP]
        
        # Check for TCP retransmissions (simplified)
        if tcp.flags == 'R':  # Reset flag
            self.anomalies.append({
                'type': 'TCP',
                'description': 'TCP connection reset',
                'src_ip': packet[scapy.IP].src,
                'dst_ip': packet[scapy.IP].dst,
                'sport': tcp.sport,
                'dport': tcp.dport
            })
            
        # Check for unusual window sizes
        if tcp.window < 100:  # Very small window size
            self.anomalies.append({
                'type': 'TCP',
                'description': 'Very small TCP window size',
                'src_ip': packet[scapy.IP].src,
                'dst_ip': packet[scapy.IP].dst,
                'window_size': tcp.window
            })
            
    def _check_icmp_anomalies(self, packet):
        """Check for ICMP-related issues"""
        icmp = packet[scapy.ICMP]
        
        # Check for ICMP flood (simplified)
        # This would need more sophisticated detection in a real system
        if icmp.type == 8:  # Echo request (ping)
            self.anomalies.append({
                'type': 'ICMP',
                'description': 'ICMP echo request detected',
                'src_ip': packet[scapy.IP].src,
                'dst_ip': packet[scapy.IP].dst
            })
            
    def generate_report(self):
        """Generate a summary report of the analysis"""
        if not self.packets:
            return "No packets analyzed"
            
        report = []
        report.append("=" * 50)
        report.append("PACKET ANALYSIS REPORT")
        report.append("=" * 50)
        report.append(f"Total packets: {len(self.packets)}")
        report.append(f"Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Protocol distribution
        report.append("Protocol Distribution:")
        for proto, count in self.protocol_stats.items():
            protocol_name = self._get_protocol_name(proto)
            report.append(f"  {protocol_name}: {count} packets")
        report.append("")
        
        # Anomalies
        report.append(f"Anomalies detected: {len(self.anomalies)}")
        for anomaly in self.anomalies:
            report.append(f"  [{anomaly['type']}] {anomaly['description']}")
            if 'src_ip' in anomaly:
                report.append(f"    Source: {anomaly['src_ip']}")
            if 'dst_ip' in anomaly:
                report.append(f"    Destination: {anomaly['dst_ip']}")
        report.append("")
        
        return "\n".join(report)
        
    def _get_protocol_name(self, proto_num):
        """Convert protocol number to name"""
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocol_map.get(proto_num, f'Unknown ({proto_num})')
        
    def visualize_data(self):
        """Create simple visualizations of the network data"""
        if not self.packets:
            logger.warning("No packets to visualize")
            return
            
        # Protocol distribution pie chart
        protocols = []
        counts = []
        for proto, count in self.protocol_stats.items():
            protocols.append(self._get_protocol_name(proto))
            counts.append(count)
            
        if protocols:
            plt.figure(figsize=(10, 5))
            
            plt.subplot(1, 2, 1)
            plt.pie(counts, labels=protocols, autopct='%1.1f%%')
            plt.title('Protocol Distribution')
            
            # Anomaly types bar chart
            if self.anomalies:
                anomaly_types = Counter([a['type'] for a in self.anomalies])
                plt.subplot(1, 2, 2)
                plt.bar(anomaly_types.keys(), anomaly_types.values())
                plt.title('Anomaly Types')
                plt.xlabel('Anomaly Type')
                plt.ylabel('Count')
                
            plt.tight_layout()
            plt.savefig('network_analysis.png')
            logger.info("Visualization saved as network_analysis.png")
            
    def save_results(self, filename=None):
        """Save analysis results to a file"""
        if filename is None:
            filename = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
        report = self.generate_report()
        with open(filename, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {filename}")
        
        # Also save anomalies to CSV for further analysis
        if self.anomalies:
            df = pd.DataFrame(self.anomalies)
            csv_filename = filename.replace('.txt', '.csv')
            df.to_csv(csv_filename, index=False)
            logger.info(f"Anomalies data saved to {csv_filename}")

def main():
    """Main function to run the packet analyzer"""
    parser = argparse.ArgumentParser(description='Packet Analyzer and Anomaly Detection Tool')
    parser.add_argument('-c', '--capture', type=int, default=0, 
                        help='Number of packets to capture (0 to read from file)')
    parser.add_argument('-f', '--file', help='PCAP file to read')
    parser.add_argument('-i', '--interface', help='Network interface to capture from')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--visualize', action='store_true', help='Generate visualizations')
    
    args = parser.parse_args()
    
    analyzer = PacketAnalyzer()
    
    # Capture or read packets
    if args.capture > 0:
        if not analyzer.capture_packets(count=args.capture, interface=args.interface):
            return
    elif args.file:
        if not analyzer.read_pcap(args.file):
            return
    else:
        print("Please specify either -c to capture packets or -f to read from a file")
        return
        
    # Analyze packets
    analyzer.analyze_packets()
    
    # Generate and display report
    report = analyzer.generate_report()
    print(report)
    
    # Save results
    analyzer.save_results(args.output)
    
    # Generate visualizations if requested
    if args.visualize:
        analyzer.visualize_data()
        
    print(f"\nAnalysis complete. Check the report for details.")

if __name__ == "__main__":
    main()