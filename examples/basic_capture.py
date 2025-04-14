#!/usr/bin/env python3
"""
Basic Packet Capture Example

This script demonstrates the most fundamental operations of the packet capture
and analysis tool. It captures packets from a specified interface or
a provided PCAP file and displays basic information about them.
"""

import argparse
import time
import logging
from datetime import datetime

import scapy.all as scapy
from rich.console import Console
from rich.table import Table

from src.protocol_parser.parser import ProtocolParser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

console = Console()


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Basic packet capture example")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-i", "--interface", help="Network interface to capture packets from"
    )
    group.add_argument("-f", "--file", help="PCAP file to read packets from")
    parser.add_argument(
        "-c", "--count", type=int, default=10, help="Number of packets to capture"
    )
    parser.add_argument("--filter", help="BPF filter to apply to the capture")
    return parser.parse_args()


def display_packet_info(packet, protocol_parser):
    """Display basic information about a packet."""
    timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S.%f")
    
    # Parse the packet using our protocol parser
    parsed_protocols = protocol_parser.parse_packet(packet)
    
    # Create a table for this packet
    table = Table(title=f"Packet captured at {timestamp}")
    table.add_column("Protocol", style="cyan")
    table.add_column("Info", style="green")
    table.add_column("Headers", style="yellow")
    
    # Check if the packet contains IP
    if "ip" in parsed_protocols:
        ip_info = parsed_protocols["ip"]
        table.add_row(
            "IP",
            f"{ip_info.version}",
            f"src={ip_info.headers['src']}, dst={ip_info.headers['dst']}, ttl={ip_info.headers['ttl']}"
        )

    # Check for transport layer protocols
    for proto in ["tcp", "udp", "icmp"]:
        if proto in parsed_protocols:
            proto_info = parsed_protocols[proto]
            if proto == "tcp":
                table.add_row(
                    "TCP",
                    f"Length: {proto_info.metadata['length']}",
                    f"sport={proto_info.headers['sport']}, dport={proto_info.headers['dport']}, flags={proto_info.headers['flags']}"
                )
            elif proto == "udp":
                table.add_row(
                    "UDP",
                    f"Length: {proto_info.metadata['length']}",
                    f"sport={proto_info.headers['sport']}, dport={proto_info.headers['dport']}, len={proto_info.headers['len']}"
                )
            elif proto == "icmp":
                table.add_row(
                    "ICMP",
                    f"Length: {proto_info.metadata['length']}",
                    f"type={proto_info.headers['type']}, code={proto_info.headers['code']}"
                )

    # Check for application layer protocols
    for proto in ["http", "dns", "smtp"]:
        if proto in parsed_protocols:
            proto_info = parsed_protocols[proto]
            if proto == "http":
                status = ""
                if "is_request" in proto_info.metadata and proto_info.metadata["is_request"]:
                    if "method" in proto_info.headers:
                        status = f"Request: {proto_info.headers['method']} {proto_info.headers.get('path', '')}"
                else:
                    if "status_code" in proto_info.headers:
                        status = f"Response: {proto_info.headers['status_code']} {proto_info.headers.get('status_text', '')}"
                        
                table.add_row(
                    "HTTP",
                    status,
                    f"version={proto_info.version or 'unknown'}"
                )
            elif proto == "dns":
                query_type = "Response" if proto_info.headers.get("qr") == 1 else "Query"
                queries = proto_info.headers.get("queries", [])
                query_names = [q["name"] for q in queries] if queries else []
                
                table.add_row(
                    "DNS",
                    f"{query_type}, ID: {proto_info.headers['id']}",
                    f"queries={', '.join(query_names) if query_names else 'none'}"
                )
            elif proto == "smtp":
                if proto_info.metadata.get("is_command"):
                    command = proto_info.headers.get("command", "unknown")
                    table.add_row(
                        "SMTP",
                        f"Command: {command}",
                        f"parameter={proto_info.headers.get('parameter', '')}"
                    )
                elif proto_info.metadata.get("is_response"):
                    table.add_row(
                        "SMTP",
                        f"Response: {proto_info.headers.get('response_code', '')}",
                        f"message={proto_info.headers.get('response_message', '')}"
                    )

    # Fingerprinted protocols
    for proto_name, proto_info in parsed_protocols.items():
        if (proto_name not in ["ip", "tcp", "udp", "icmp", "http", "dns", "smtp"] and 
            proto_info.fingerprint):
            table.add_row(
                proto_name.upper(),
                f"Confidence: {proto_info.confidence:.2f}",
                f"Fingerprinted: {proto_info.fingerprint}"
            )
                
    console.print(table)
    console.print("")


def capture_from_interface(interface, count, bpf_filter, protocol_parser):
    """Capture packets from a network interface."""
    console.print(f"[bold]Capturing {count} packets from interface {interface}...[/bold]")
    if bpf_filter:
        console.print(f"[bold]Using filter: {bpf_filter}[/bold]")
    
    def packet_callback(packet):
        nonlocal packets_captured
        display_packet_info(packet, protocol_parser)
        packets_captured += 1
        if packets_captured >= count:
            return True  # Signal to stop sniffing
    
    packets_captured = 0
    scapy.sniff(iface=interface, prn=packet_callback, filter=bpf_filter, store=0, count=count)
    console.print("[bold green]Capture complete![/bold green]")


def read_from_pcap(file_path, count, protocol_parser):
    """Read packets from a PCAP file."""
    console.print(f"[bold]Reading {count} packets from file {file_path}...[/bold]")
    
    try:
        # Read the PCAP file
        packets = scapy.rdpcap(file_path)
        
        # Limit to the requested number of packets
        packets = packets[:count]
        
        for i, packet in enumerate(packets):
            console.print(f"[bold]Packet {i+1}/{len(packets)}[/bold]")
            display_packet_info(packet, protocol_parser)
            time.sleep(0.1)  # Brief pause between packets for readability
            
        console.print("[bold green]Finished reading packets![/bold green]")
        
    except FileNotFoundError:
        console.print(f"[bold red]Error: File {file_path} not found![/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error reading PCAP file: {str(e)}[/bold red]")


def main():
    """Main function."""
    args = parse_arguments()
    
    # Initialize the protocol parser
    protocol_parser = ProtocolParser()
    
    # Display supported protocols
    supported_protocols = protocol_parser.get_supported_protocols()
    console.print(f"[bold]Supported protocols: {', '.join(supported_protocols)}[/bold]")
    
    if args.interface:
        capture_from_interface(args.interface, args.count, args.filter, protocol_parser)
    elif args.file:
        read_from_pcap(args.file, args.count, protocol_parser)


if __name__ == "__main__":
    main()

