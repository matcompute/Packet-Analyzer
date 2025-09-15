#!/usr/bin/env python3
"""
Simple script to generate test network traffic
"""
import os
import time
import subprocess
import sys

def generate_test_traffic():
    """Generate some test network traffic"""
    print("Generating test traffic...")
    
    # Try to generate some DNS traffic
    try:
        # This will generate DNS requests
        import socket
        socket.gethostbyname('google.com')
        socket.gethostbyname('github.com')
        socket.gethostbyname('stackoverflow.com')
        print("Generated DNS traffic")
    except:
        pass
    
    # Try to ping (ICMP)
    try:
        if os.name == 'nt':  # Windows
            subprocess.run(['ping', '-n', '2', '8.8.8.8'], timeout=5, capture_output=True)
        else:  # Linux/Mac
            subprocess.run(['ping', '-c', '2', '8.8.8.8'], timeout=5, capture_output=True)
        print("Generated ICMP traffic")
    except:
        pass
    
    print("Test traffic generation completed")

if __name__ == "__main__":
    generate_test_traffic()