#!/usr/bin/env python3
"""
Advanced Protocol Analysis Example

This script demonstrates detailed protocol-specific analysis using the
network protocol analyzer. It performs deep packet inspection, protocol
fingerprinting, statistical analysis, and visualizes protocol-specific data.
"""

import argparse
import logging
import time
from datetime import datetime
from collections import Counter, defaultdict
import json
from typing import Dict, List, Any, Tuple

import scapy.all as scapy
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.table import Table
from rich.syntax import Syntax
from rich.tree import Tree
from rich import box

from src.protocol_parser.parser import ProtocolParser, ProtocolInfo

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

console = Console()


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Advanced protocol analysis example")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-i", "--interface", help="Network interface to capture packets from"
    )
    group.add_argument("-f", "--file", help="PCAP file to read packets from")
    parser.add_argument(
        "-c", "--count", type=int, default=100, help="Number of packets to analyze"
    )
    parser.add_argument("--filter", help="BPF filter to apply to the capture")
    parser.add_argument(
        "--protocol", 
        choices=["http", "dns", "smtp", "all"],
        default="all",
        help="Protocol to focus analysis on"
    )
    return parser.parse_args()


class ProtocolAnalyzer:
    """Analyzes protocols from captured packets."""
    
    def __init__(self):
        """Initialize the protocol analyzer."""
        self.protocol_parser = ProtocolParser()
        self.packets = []
        self.parsed_protocols = []
        self.statistics = {
            "protocol_counts": Counter(),
            "top_ip_sources": Counter(),
            "top_ip_destinations": Counter(),
            "top_tcp_ports": Counter(),
            "top_udp_ports": Counter(),
            "http_methods": Counter(),
            "http_status_codes": Counter(),
            "dns_query_types": Counter(),
            "dns_domains": Counter(),
            "smtp_commands": Counter(),
        }
        self.traffic_patterns = {
            "ip_conversations": defaultdict(int),
            "port_activity": defaultdict(int),
            "temporal_distribution": defaultdict(int),
            "protocol_sequence": [],
        }
        self.fingerprint_results = []
    
    def add_packet(self, packet):
        """Add a packet for analysis."""
        self.packets.append(packet)
        timestamp = int(packet.time)
        
        # Parse the packet
        parsed = self.protocol_parser.parse_packet(packet)
        self.parsed_protocols.append(parsed)
        
        # Update protocol statistics
        for proto_name in parsed.keys():
            self.statistics["protocol_counts"][proto_name] += 1
        
        # Update temporal distribution
        self.traffic_patterns["temporal_distribution"][timestamp] += 1
        
        # Update protocol sequence for pattern detection
        self.traffic_patterns["protocol_sequence"].append(list(parsed.keys()))
        
        # Protocol-specific statistics
        if "ip" in parsed:
            ip_info = parsed["ip"]
            src = ip_info.headers["src"]
            dst = ip_info.headers["dst"]
            self.statistics["top_ip_sources"][src] += 1
            self.statistics["top_ip_destinations"][dst] += 1
            
            # Track IP conversations
            conv_key = tuple(sorted([src, dst]))
            self.traffic_patterns["ip_conversations"][conv_key] += 1
        
        if "tcp" in parsed:
            tcp_info = parsed["tcp"]
            sport = tcp_info.headers["sport"]
            dport = tcp_info.headers["dport"]
            self.statistics["top_tcp_ports"][dport] += 1
            
            # Track port activity
            self.traffic_patterns["port_activity"][f"TCP:{dport}"] += 1
        
        if "udp" in parsed:
            udp_info = parsed["udp"]
            sport = udp_info.headers["sport"]
            dport = udp_info.headers["dport"]
            self.statistics["top_udp_ports"][dport] += 1
            
            # Track port activity
            self.traffic_patterns["port_activity"][f"UDP:{dport}"] += 1
        
        if "http" in parsed:
            http_info = parsed["http"]
            if http_info.metadata.get("is_request") and "method" in http_info.headers:
                self.statistics["http_methods"][http_info.headers["method"]] += 1
            elif "status_code" in http_info.headers:
                self.statistics["http_status_codes"][http_info.headers["status_code"]] += 1
        
        if "dns" in parsed:
            dns_info = parsed["dns"]
            for query in dns_info.headers.get("queries", []):
                qname = query.get("name", "")
                qtype = query.get("type", 0)
                if qname:
                    self.statistics["dns_domains"][qname] += 1
                if qtype:
                    self.statistics["dns_query_types"][qtype] += 1
        
        if "smtp" in parsed:
            smtp_info = parsed["smtp"]
            if smtp_info.metadata.get("is_command") and "command" in smtp_info.headers:
                self.statistics["smtp_commands"][smtp_info.headers["command"]] += 1
        
        # Perform fingerprinting if needed
        if not any(p in parsed for p in ["http", "dns", "smtp"]):
            fingerprints = self.protocol_parser.fingerprint_packet(packet)
            if fingerprints:
                self.fingerprint_results.append((packet, fingerprints))
    
    def get_protocol_statistics(self):
        """Get statistics about observed protocols."""
        stats_table = Table(title="Protocol Statistics", box=box.SIMPLE)
        stats_table.add_column("Category", style="cyan")
        stats_table.add_column("Details", style="green")
        
        # Protocol distribution
        proto_dist = ", ".join([f"{p}: {c}" for p, c in self.statistics["protocol_counts"].most_common()])
        stats_table.add_row("Protocol Distribution", proto_dist)
        
        # IP statistics
        top_sources = ", ".join([f"{ip}: {count}" for ip, count in self.statistics["top_ip_sources"].most_common(5)])
        top_destinations = ", ".join([f"{ip}: {count}" for ip, count in self.statistics["top_ip_destinations"].most_common(5)])
        stats_table.add_row("Top IP Sources", top_sources)
        stats_table.add_row("Top IP Destinations", top_destinations)
        
        # Port statistics
        top_tcp = ", ".join([f"{port}: {count}" for port, count in self.statistics["top_tcp_ports"].most_common(5)])
        top_udp = ", ".join([f"{port}: {count}" for port, count in self.statistics["top_udp_ports"].most_common(5)])
        stats_table.add_row("Top TCP Ports", top_tcp)
        stats_table.add_row("Top UDP Ports", top_udp)
        
        # HTTP statistics
        if self.statistics["http_methods"]:
            methods = ", ".join([f"{m}: {c}" for m, c in self.statistics["http_methods"].most_common()])
            status_codes = ", ".join([f"{s}: {c}" for s, c in self.statistics["http_status_codes"].most_common()])
            stats_table.add_row("HTTP Methods", methods)
            stats_table.add_row("HTTP Status Codes", status_codes)
        
        # DNS statistics
        if self.statistics["dns_domains"]:
            domains = ", ".join([f"{d}: {c}" for d, c in self.statistics["dns_domains"].most_common(5)])
            qtypes = ", ".join([f"{t}: {c}" for t, c in self.statistics["dns_query_types"].most_common(5)])
            stats_table.add_row("Top DNS Domains", domains)
            stats_table.add_row("DNS Query Types", qtypes)
        
        # SMTP statistics
        if self.statistics["smtp_commands"]:
            commands = ", ".join([f"{cmd}: {c}" for cmd, c in self.statistics["smtp_commands"].most_common()])
            stats_table.add_row("SMTP Commands", commands)
        
        return stats_table
    
    def detect_traffic_patterns(self):
        """Detect and report on traffic patterns."""
        patterns_table = Table(title="Traffic Patterns", box=box.SIMPLE)
        patterns_table.add_column("Pattern Type", style="cyan")
        patterns_table.add_column("Description", style="green")
        
        # Analyze IP conversations
        top_conversations = sorted(
            self.traffic_patterns["ip_conversations"].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5]
        
        if top_conversations:
            conv_str = "\n".join([f"{ip1} <-> {ip2}: {count} packets" for (ip1, ip2), count in top_conversations])
            patterns_table.add_row("Top IP Conversations", conv_str)
        
        # Detect port scanning
        port_scan_threshold = 10  # Adjust based on typical behavior
        potential_scanners = {}
        
        for i, parsed in enumerate(self.parsed_protocols):
            if "ip" in parsed and "tcp" in parsed:
                src_ip = parsed["ip"].headers["src"]
                if src_ip not in potential_scanners:
                    potential_scanners[src_ip] = set()
                potential_scanners[src_ip].add(parsed["tcp"].headers["dport"])
        
        scanners = [ip for ip, ports in potential_scanners.items() if len(ports) > port_scan_threshold]
        if scanners:
            patterns_table.add_row(
                "Potential Port Scanning", 
                "\n".join([f"{ip}: {len(potential_scanners[ip])} unique ports" for ip in scanners])
            )
        
        # Detect protocol anomalies (rapid protocol switching)
        protocol_sequences = self.traffic_patterns["protocol_sequence"]
        if len(protocol_sequences) > 10:
            rapid_switches = 0
            for i in range(1, len(protocol_sequences)):
                if set(protocol_sequences[i]) != set(protocol_sequences[i-1]):
                    rapid_switches += 1
            
            if rapid_switches > len(protocol_sequences) * 0.7:  # 70% of packets have protocol changes
                patterns_table.add_row(
                    "Protocol Anomaly", 
                    f"Frequent protocol changes detected ({rapid_switches} switches in {len(protocol_sequences)} packets)"
                )
        
        # Connection spikes
        time_counts = sorted(self.traffic_patterns["temporal_distribution"].items())
        if len(time_counts) > 5:
            max_count = max(count for _, count in time_counts)
            avg_count = sum(count for _, count in time_counts) / len(time_counts)
            
            if max_count > avg_count * 3:  # Significant spike
                spike_times = [
                    datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                    for ts, count in time_counts
                    if count > avg_count * 2
                ]
                if spike_times:
                    patterns_table.add_row(
                        "Traffic Spikes", 
                        f"Abnormal traffic volume detected at: {', '.join(spike_times)}"
                    )
        
        return patterns_table
    
    def display_deep_inspection_results(self, protocol_filter="all"):
        """Display deep packet inspection results."""
        dpi_tree = Tree("Deep Packet Inspection Results")
        
        for i, (packet, parsed) in enumerate(zip(self.packets, self.parsed_protocols)):
            # Filter by protocol if needed
            if protocol_filter != "all" and protocol_filter not in parsed:
                continue
                
            packet_node = dpi_tree.add(f"Packet {i+1} - {datetime.fromtimestamp(packet.time).strftime('%H:%M:%S')}")
            
            for proto_name, proto_info in parsed.items():
                if not proto_info.dpi_results:
                    continue
                    
                proto_node = packet_node.add(f"[bold]{proto_name.upper()}[/bold]")
                
                for category, results in proto_info.dpi_results.items():
                    if isinstance(results, dict):
                        cat_node = proto_node.add(f"[cyan]{category}[/cyan]")
                        for key, value in results.items():
                            cat_node.add(f"[green]{key}[/green]: {value}")
                    else:
                        proto_node.add(f"[cyan]{category}[/cyan]: {results}")
        
        return dpi_tree
    
    def display_protocol_details(self, protocol_name):
        """Display detailed information for a specific protocol."""
        if protocol_name == "http":
            return self._display_http_details()
        elif protocol_name == "dns":
            return self._display_dns_details()
        elif protocol_name == "smtp":
            return self._display_smtp_details()
        else:
            return Panel(f"No detailed view available for {protocol_name}")
    
    def _display_http_details(self):
        """Display detailed HTTP information."""
        http_table = Table(title="HTTP Traffic Analysis", box=box.SIMPLE)
        http_table.add_column("ID", style="cyan")
        http_table.add_column("Type", style="green")
        http_table.add_column("Method/Status", style="yellow")
        http_table.add_column("Path/Message", style="magenta")
        http_table.add_column("Headers", style="blue")
        
        http_found = False
        
        for i, parsed in enumerate(self.parsed_protocols):
            if "http" not in parsed:
                continue
                
            http_found = True
            http_info = parsed["http"]
            
            # Determine if request or response
            if http_info.metadata.get("is_request", False):
                req_type = "Request"
                method = http_info.headers.get("method", "?")
                path = http_info.headers.get("path", "?")
                status = f"{method}"
                message = f"{path}"
            else:
                req_type = "Response"
                status_code = http_info.headers.get("status_code", "?")
                status_text = http_info.headers.get("status_text", "?")
                status = f"{status_code}"
                message = f"{status_text}"
            
            # Get important headers
            header_list = []
            for key, value in http_info.headers.items():
                if key not in ["method", "path", "status_code", "status_text"]:
                    header_list.append(f"{key}: {value}")
            
            headers_str = "\n".join(header_list[:5])  # Limit to 5 headers for display
            if len(header_list) > 5:
                headers_str += f"\n... ({len(header_list) - 5} more)"
            
            http_table.add_row(str(i), req_type, status, message, headers_str)
        
        if not http_found:
            http_table.add_row("N/A", "N/A", "N/A", "No HTTP traffic found", "N/A")
            
        return http_table
    
    def _display_dns_details(self):
        """Display detailed DNS information."""
        dns_table = Table(title="DNS Traffic Analysis", box=box.SIMPLE)
        dns_table.add_column("ID", style="cyan")
        dns_table.add_column("Type", style="green")
        dns_table.add_column("Domain", style="yellow")
        dns_table.add_column("Record Type", style="magenta")
        dns_table.add_column("Response Data", style="blue")
        
        dns_found = False
        
        for i, parsed in enumerate(self.parsed_protocols):
            if "dns" not in parsed:
                continue
                
            dns_found = True
            dns_info = parsed["dns"]
            
            # Determine if query or response
            is_response = dns_info.headers.get("qr") == 1
            query_type = "Response" if is_response else "Query"
            
            # Process queries and answers
            queries = dns_info.headers.get("queries", [])
            answers = dns_info.headers.get("answers", [])
            
            if queries:
                for query in queries:
                    qname = query.get("name", "?")
                    qtype = query.get("type", "?")
                    
                    # Find corresponding answer if this is a response
                    answer_data = "N/A"
                    if is_response and answers:
                        for answer in answers:
                            if answer.get("name") == qname:
                                answer_data = answer.get("data", "?")
                                break
                    
                    dns_table.add_row(str(i), query_type, qname, str(qtype), answer_data)
            elif answers:  # Response without query section
                for answer in answers:
                    rname = answer.get("name", "?")
                    rtype = answer.get("type", "?")
                    rdata = answer.get("data", "?")
                    
                    dns_table.add_row(str(i), "Response", rname, str(rtype), str(rdata))
            else:
                dns_table.add_row(str(i), query_type, "No query/answer data", "", "")
        
        if not dns_found:
            dns_table.add_row("N/A", "N/A", "No DNS traffic found", "N/A", "N/A")
            
        return dns_table
    
    def _display_smtp_details(self):
        """Display detailed SMTP information."""
        smtp_table = Table(title="SMTP Traffic Analysis", box=box.SIMPLE)
        smtp_table.add_column("ID", style="cyan")
        smtp_table.add_column("Type", style="green")
        smtp_table.add_column("Command/Code", style="yellow")
        smtp_table.add_column("Parameter/Message", style="magenta")
        smtp_table.add_column("Additional Info", style="blue")
        
        smtp_found = False
        
        for i, parsed in enumerate(self.parsed_protocols):
            if "smtp" not in parsed:
                continue
                
            smtp_found = True
            smtp_info = parsed["smtp"]
            
            # Check if command or response
            if smtp_info.metadata.get("is_command"):
                type_str = "Command"
                command = smtp_info.headers.get("command", "?")
                parameter = smtp_info.headers.get("parameter", "")
                
                # Add additional info based on command type
                additional = ""
                if command == "MAIL FROM" and parameter:
                    additional = f"Sender: {parameter}"
                elif command == "RCPT TO" and parameter:
                    additional = f"Recipient: {parameter}"
                elif command == "DATA":
                    # Look for email content or attachments in DPI results
                    has_attachment = smtp_info.dpi_results.get("has_attachment", False)
                    is_multipart = smtp_info.dpi_results.get("is_multipart", False)
                    additional = f"Attachments: {'Yes' if has_attachment else 'No'}, Multipart: {'Yes' if is_multipart else 'No'}"
                
                smtp_table.add_row(str(i), type_str, command, parameter, additional)
                
            elif smtp_info.metadata.get("is_response"):
                type_str = "Response"
                code = smtp_info.headers.get("response_code", "?")
                message = smtp_info.headers.get("response_message", "")
                
                # Add context to response codes
                additional = ""
                if code == "220":
                    additional = "Server greeting"
                elif code == "250":
                    additional = "Requested action completed"
                elif code == "354":
                    additional = "Start mail input"
                elif code == "221":
                    additional = "Service closing transmission channel"
                elif code == "550":
                    additional = "Requested action not taken (mailbox unavailable)"
                
                smtp_table.add_row(str(i), type_str, code, message, additional)
            
            else:
                # Raw SMTP data (might be content)
                data_excerpt = str(smtp_info.data[:50]) + "..." if smtp_info.data and len(smtp_info.data) > 50 else str(smtp_info.data)
                smtp_table.add_row(str(i), "Data", "", data_excerpt, "")
        
        if not smtp_found:
            smtp_table.add_row("N/A", "N/A", "No SMTP traffic found", "N/A", "N/A")
            
        return smtp_table
    
    def display_fingerprint_results(self):
        """Display protocol fingerprinting results."""
        if not self.fingerprint_results:
            return Panel("No fingerprinting results available")
            
        fp_table = Table(title="Protocol Fingerprinting Results", box=box.SIMPLE)
        fp_table.add_column("Packet ID", style="cyan")
        fp_table.add_column("Protocol", style="green")
        fp_table.add_column("Confidence", style="yellow")
        fp_table.add_column("Source Port", style="magenta")
        fp_table.add_column("Destination Port", style="blue")
        
        for i, (packet, fingerprints) in enumerate(self.fingerprint_results):
            src_port = dst_port = "?"
            
            # Try to get port information
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
            # Add each fingerprint result
            for proto, confidence in fingerprints:
                fp_table.add_row(
                    str(i),
                    proto.upper(),
                    f"{confidence:.2f}",
                    str(src_port),
                    str(dst_port)
                )
                
        return fp_table


def capture_and_analyze(interface=None, pcap_file=None, packet_count=100, bpf_filter=None, protocol_filter="all"):
    """Capture packets and perform protocol analysis."""
    analyzer = ProtocolAnalyzer()
    
    if interface:
        console.print(f"[bold]Capturing {packet_count} packets from interface {interface}...[/bold]")
        if bpf_filter:
            console.print(f"[bold]Using filter: {bpf_filter}[/bold]")
        
        def packet_callback(packet):
            nonlocal packets_captured
            analyzer.add_packet(packet)
            packets_captured += 1
            if packets_captured >= packet_count:
                return True  # Signal to stop sniffing
        
        packets_captured = 0
        try:
            scapy.sniff(iface=interface, prn=packet_callback, filter=bpf_filter, store=0, count=packet_count)
        except Exception as e:
            console.print(f"[bold red]Error during packet capture: {e}[/bold red]")
            return
            
    elif pcap_file:
        console.print(f"[bold]Reading packets from file {pcap_file}...[/bold]")
        try:
            packets = scapy.rdpcap(pcap_file)
            packets = packets[:packet_count]  # Limit to requested count
            
            for packet in packets:
                analyzer.add_packet(packet)
                
        except Exception as e:
            console.print(f"[bold red]Error reading PCAP file: {e}[/bold red]")
            return
    
    # Display results
    layout = Layout()
    layout.split_column(
        Layout(name="header"),
        Layout(name="statistics"),
        Layout(name="patterns"),
        Layout(name="protocols"),
        Layout(name="fingerprinting"),
        Layout(name="dpi")
    )
    
    layout["header"].update(Panel(f"Protocol Analysis Results - {len(analyzer.packets)} packets"))
    layout["statistics"].update(analyzer.get_protocol_statistics())
    layout["patterns"].update(analyzer.detect_traffic_patterns())
    
    # Protocol-specific analysis based on filter
    if protocol_filter == "all":
        # Show summary of each protocol
        protocols_layout = Layout()
        protocols_layout.split_row(
            Layout(name="http"),
            Layout(name="dns"),
            Layout(name="smtp")
        )
        
        protocols_layout["http"].update(analyzer._display_http_details())
        protocols_layout["dns"].update(analyzer._display_dns_details())
        protocols_layout["smtp"].update(analyzer._display_smtp_details())
        
        layout["protocols"].update(protocols_layout)
    else:
        # Show detailed view of specific protocol
        layout["protocols"].update(analyzer.display_protocol_details(protocol_filter))
    
    layout["fingerprinting"].update(analyzer.display_fingerprint_results())
    layout["dpi"].update(analyzer.display_deep_inspection_results(protocol_filter))
    
    console.print(layout)


def main():
    """Main function."""
    args = parse_arguments()
    
    if args.interface:
        capture_and_analyze(
            interface=args.interface,
            packet_count=args.count,
            bpf_filter=args.filter,
            protocol_filter=args.protocol
        )
    elif args.file:
        capture_and_analyze(
            pcap_file=args.file,
            packet_count=args.count,
            protocol_filter=args.protocol
        )


if __name__ == "__main__":
    main()
