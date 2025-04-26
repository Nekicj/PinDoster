#!/usr/bin/env python3
from scapy.all import show_interfaces

if __name__ == "__main__":
    print("Available Network Interfaces:")
    print("-----------------------------")
    show_interfaces()

