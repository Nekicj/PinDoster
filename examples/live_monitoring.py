#!/usr/bin/env python3
"""
Live Network Monitoring Example

This script demonstrates real-time network traffic monitoring and visualization,
providing a comprehensive dashboard for analyzing protocols, bandwidth usage,
and detecting suspicious patterns.
"""

import argparse
import logging
import time
import threading
import signal
import sys
import os
from datetime import datetime, timedelta
from collections import Counter, defaultdict, deque
import asyncio
from typing import Dict, List, Set, Tuple, Any, Optional
import math

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import psutil

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.columns import Columns
from rich.align import Align
from rich import box

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
    parser = argparse.ArgumentParser(description="Live Network Monitor")
    parser.add_argument(
        "-i", "--interface", required=True,
        help="Network interface to monitor"
    )
    parser.add_argument(
        "--refresh-interval", type=float, default=1.0,
        help="Dashboard refresh interval in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--buffer-size", type=int, default=1000,
        help="Number of packets to keep in memory for analysis (default: 1000)"
    )
    parser.add_argument(
        "--filter", default="",
        help="BPF filter to apply to the capture"
    )
    parser.add_argument(
        "--alert-threshold", type=int, default=5,
        help="Threshold for traffic spike alerts (multiplier of average) (default: 5)"
    )
    return parser.parse_args()


class RealTimeNetworkMonitor:
    """Real-time network traffic monitor with analysis capabilities."""
    
    def __init__(self, interface: str, buffer_size: int = 1000, alert_threshold: int = 5):
        """Initialize the network monitor.
        
        Args:
            interface: Network interface to monitor
            buffer_size: Maximum number of packets to keep in memory
            alert_threshold: Multiplier of average traffic to trigger alert
        """
        self.interface = interface
        self.buffer_size = buffer_size
        self.alert_threshold = alert_threshold
        
        # Initialize protocol parser
        self.protocol_parser = ProtocolParser()
        
        # Packet storage
        self.packets = deque(maxlen=buffer_size)
        self.parsed_packets = deque(maxlen=buffer_size)
        
        # Metrics
        self.total_packets = 0
        self.bytes_received = 0
        self.start_time = time.time()
        self.packet_timestamps = deque(maxlen=buffer_size)
        
        # Bandwidth metrics (last 60 seconds with 1-second granularity)
        self.bandwidth_history = deque(maxlen=60)
        self.current_bandwidth = 0
        self.last_bandwidth_update = time.time()
        self.bandwidth_update_interval = 1.0  # seconds
        
        # Protocol stats
        self.protocol_counts = Counter()
        self.ip_sources = Counter()
        self.ip_destinations = Counter()
        self.tcp_ports = Counter()
        self.udp_ports = Counter()
        
        # Connection tracking
        self.active_connections = {}  # (src_ip, src_port, dst_ip, dst_port) -> connection info
        self.connection_timeout = 60  # seconds
        
        # Alert system
        self.alerts = deque(maxlen=20)  # Keep the last 20 alerts
        self.traffic_baseline = None
        self.traffic_history = deque(maxlen=30)  # Keep 30 seconds of traffic counts
        
        # Pattern detection
        self.port_scan_threshold = 10  # Unique ports per IP to trigger alert
        self.port_scan_window = 5  # seconds
        self.ip_scan_threshold = 10  # Unique IPs per source to trigger alert
        self.potential_scanners = {}  # ip -> set of ports
        self.potential_ip_scanners = {}  # ip -> set of target IPs
        
        # Search and filter
        self.packet_filter = lambda p: True  # Default filter passes all packets
        self.highlight_filter = lambda p: False  # Default highlight filter
        
        # Control flags
        self.running = False
        self.sniffer_thread = None
        self.analyzer_thread = None
        self.lock = threading.RLock()
    
    def start_capture(self, bpf_filter: str = ""):
        """Start capturing packets from the interface.
        
        Args:
            bpf_filter: BPF filter to apply
        """
        self.running = True
        
        # Start sniffing in a separate thread
        self.sniffer_thread = threading.Thread(
            target=self._sniff_packets,
            args=(bpf_filter,),
            daemon=True
        )
        self.sniffer_thread.start()
        
        # Start periodic analysis
        self.analyzer_thread = threading.Thread(
            target=self._periodic_analysis,
            daemon=True
        )
        self.analyzer_thread.start()
        
        logger.info(f"Started capturing on interface {self.interface}")
    
    def stop_capture(self):
        """Stop packet capture."""
        self.running = False
        
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=1.0)
        
        if self.analyzer_thread:
            self.analyzer_thread.join(timeout=1.0)
        
        logger.info("Stopped capturing")
    
    def _sniff_packets(self, bpf_filter: str):
        """Sniff packets from the interface and process them.
        
        Args:
            bpf_filter: BPF filter to apply
        """
        def packet_callback(packet):
            """Process a captured packet."""
            if not self.running:
                return True  # Stop sniffing
            
            with self.lock:
                self._process_packet(packet)
                
            return None  # Continue sniffing
        
        try:
            # Start sniffing with our callback
            scapy.sniff(
                iface=self.interface,
                prn=packet_callback,
                filter=bpf_filter,
                store=0
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.running = False
    
    def _process_packet(self, packet):
        """Process a captured packet and update metrics.
        
        Args:
            packet: Scapy packet to process
        """
        # Add packet to storage
        self.packets.append(packet)
        self.packet_timestamps.append(time.time())
        
        # Update basic metrics
        self.total_packets += 1
        packet_size = len(packet)
        self.bytes_received += packet_size
        
        # Parse the packet
        try:
            parsed = self.protocol_parser.parse_packet(packet)
            self.parsed_packets.append(parsed)
            
            # Update protocol stats
            for proto in parsed:
                self.protocol_counts[proto] += 1
            
            # Process IP information if available
            if "ip" in parsed:
                ip_info = parsed["ip"]
                src_ip = ip_info.headers["src"]
                dst_ip = ip_info.headers["dst"]
                
                self.ip_sources[src_ip] += 1
                self.ip_destinations[dst_ip] += 1
                
                # Track for potential IP scanning
                if src_ip not in self.potential_ip_scanners:
                    self.potential_ip_scanners[src_ip] = set()
                self.potential_ip_scanners[src_ip].add(dst_ip)
            
            # Process TCP information
            if "tcp" in parsed:
                tcp_info = parsed["tcp"]
                src_port = tcp_info.headers["sport"]
                dst_port = tcp_info.headers["dport"]
                
                self.tcp_ports[dst_port] += 1
                
                # Track connection
                if "ip" in parsed:
                    src_ip = parsed["ip"].headers["src"]
                    dst_ip = parsed["ip"].headers["dst"]
                    conn_key = (src_ip, src_port, dst_ip, dst_port)
                    
                    if conn_key not in self.active_connections:
                        self.active_connections[conn_key] = {
                            "start_time": time.time(),
                            "last_seen": time.time(),
                            "packets": 1,
                            "bytes": packet_size,
                            "state": "ESTABLISHED",
                            "protocol": "TCP"
                        }
                    else:
                        conn = self.active_connections[conn_key]
                        conn["last_seen"] = time.time()
                        conn["packets"] += 1
                        conn["bytes"] += packet_size
                        
                        # Update connection state based on TCP flags
                        if tcp_info.dpi_results.get("connections_states"):
                            conn["state"] = tcp_info.dpi_results["connections_states"]
                        
                        # Check for connection closure
                        if tcp_info.headers.get("flags", 0) & 0x01:  # FIN flag
                            conn["state"] = "CLOSING"
                        elif tcp_info.headers.get("flags", 0) & 0x04:  # RST flag
                            conn["state"] = "RESET"
                
                # Track for potential port scanning
                if "ip" in parsed:
                    src_ip = parsed["ip"].headers["src"]
                    if src_ip not in self.potential_scanners:
                        self.potential_scanners[src_ip] = set()
                    self.potential_scanners[src_ip].add(dst_port)
            
            # Process UDP information
            if "udp" in parsed:
                udp_info = parsed["udp"]
                src_port = udp_info.headers["sport"]
                dst_port = udp_info.headers["dport"]
                
                self.udp_ports[dst_port] += 1
                
                # Track connection for UDP too (though they're stateless)
                if "ip" in parsed:
                    src_ip = parsed["ip"].headers["src"]
                    dst_ip = parsed["ip"].headers["dst"]
                    conn_key = (src_ip, src_port, dst_ip, dst_port)
                    
                    if conn_key not in self.active_connections:
                        self.active_connections[conn_key] = {
                            "start_time": time.time(),
                            "last_seen": time.time(),
                            "packets": 1,
                            "bytes": packet_size,
                            "state": "ACTIVE",
                            "protocol": "UDP"
                        }
                    else:
                        conn = self.active_connections[conn_key]
                        conn["last_seen"] = time.time()
                        conn["packets"] += 1
                        conn["bytes"] += packet_size
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
        
        # Update bandwidth metrics
        current_time = time.time()
        if current_time - self.last_bandwidth_update >= self.bandwidth_update_interval:
            # Calculate bandwidth in bytes per second
            elapsed = current_time - self.last_bandwidth_update
            self.current_bandwidth = self.bytes_received / elapsed if elapsed > 0 else 0
            self.bandwidth_history.append((current_time, self.current_bandwidth))
            
            # Reset for next interval
            self.bytes_received = 0
            self.last_bandwidth_update = current_time
        
        # Update traffic history for baseline calculation
        now = time.time()
        self.traffic_history.append((now, 1))  # 1 packet at this timestamp
    
    def _periodic_analysis(self):
        """Perform periodic analysis tasks."""
        while self.running:
            try:
                with self.lock:
                    self._cleanup_expired_connections()
                    self._detect_traffic_anomalies()
                    self._detect_scanning()
            except Exception as e:
                logger.error(f"Error in periodic analysis: {e}")
            
            time.sleep(1.0)  # Run analysis every second
    
    def _cleanup_expired_connections(self):
        """Remove expired connections from tracking."""
        now = time.time()
        expired = []
        
        for conn_key, conn_info in self.active_connections.items():
            if now - conn_info["last_seen"] > self.connection_timeout:
                expired.append(conn_key)
        
        for key in expired:
            del self.active_connections[key]
    
    def _detect_traffic_anomalies(self):
        """Detect anomalies in traffic patterns and create alerts."""
        now = time.time()
        
        # Count packets in the last 5 seconds
        recent_time = now - 5
        recent_packets = sum(1 for ts, _ in self.traffic_history if ts > recent_time)
        
        # If we have enough history, calculate baseline
        if len(self.traffic_history) >= 10:
            # Calculate baseline as average packet rate over the history excluding the last 5 seconds
            # This helps detect recent spikes without them affecting the baseline immediately
            baseline_packets = sum(1 for ts, _ in self.traffic_history if ts <= recent_time)
            baseline_time = min(now - 5 - self.traffic_history[0][0], 25)  # max 25 seconds of history
            packets_per_second = baseline_packets / baseline_time if baseline_time > 0 else 0
            
            # Update baseline with exponential moving average
            if self.traffic_baseline is None:
                self.traffic_baseline = packets_per_second
            else:
                alpha = 0.3  # Smoothing factor
                self.traffic_baseline = alpha * packets_per_second + (1 - alpha) * self.traffic_baseline
            
            # Check for traffic spike (threshold times baseline)
            recent_packets_per_second = recent_packets / 5
            if self.traffic_baseline > 0 and recent_packets_per_second > self.traffic_baseline * self.alert_threshold:
                self.alerts.append({
                    "timestamp": now,
                    "type": "TRAFFIC_SPIKE",
                    "message": f"Traffic spike detected: {recent_packets_per_second:.1f} packets/sec "
                               f"(baseline: {self.traffic_baseline:.1f})",
                    "level": "WARNING"
                })
            
            # Check for unusual traffic drop
            if (self.traffic_baseline > 2.0 and  # Enough baseline to detect drops
                recent_packets_per_second < self.traffic_baseline * 0.2):  # Significant drop (80% reduction)
                self.alerts.append({
                    "timestamp": now,
                    "type": "TRAFFIC_DROP",
                    "message": f"Unusual traffic drop detected: {recent_packets_per_second:.1f} packets/sec "
                               f"(baseline: {self.traffic_baseline:.1f})",
                    "level": "INFO"
                })
    
    def _detect_scanning(self):
        """Detect potential port scanning and IP scanning activities."""
        now = time.time()
        
        # Clean up old entries in scanners to avoid false positives
        # Only keep potential scanning activity from the last window
        for ip in list(self.potential_scanners.keys()):
            # Remove scanner if no packets in port scan window
            if ip not in self.ip_sources or now - self.packet_timestamps[-1] > self.port_scan_window:
                del self.potential_scanners[ip]
        
        for ip in list(self.potential_ip_scanners.keys()):
            # Remove scanner if no packets in scan window
            if ip not in self.ip_sources or now - self.packet_timestamps[-1] > self.port_scan_window:
                del self.potential_ip_scanners[ip]
        
        # Check for port scanning (many ports, few packets per port)
        for ip, ports in self.potential_scanners.items():
            if len(ports) >= self.port_scan_threshold:
                # Verify this is recent activity
                recent_packets = sum(1 for ts in self.packet_timestamps if now - ts <= self.port_scan_window)
                if recent_packets > 0:
                    self.alerts.append({
                        "timestamp": now,
                        "type": "PORT_SCAN",
                        "message": f"Potential port scan from {ip}: {len(ports)} unique ports",
                        "level": "WARNING"
                    })
                    # Reset after alerting to avoid repeated alerts
                    self.potential_scanners[ip] = set()
        
        # Check for IP scanning (many IPs, few packets per IP)
        for ip, targets in self.potential_ip_scanners.items():
            if len(targets) >= self.ip_scan_threshold:
                # Verify this is recent activity
                recent_packets = sum(1 for ts in self.packet_timestamps if now - ts <= self.port_scan_window)
                if recent_packets > 0:
                    self.alerts.append({
                        "timestamp": now,
                        "type": "IP_SCAN",
                        "message": f"Potential IP scan from {ip}: {len(targets)} unique targets",
                        "level": "WARNING"
                    })
                    # Reset after alerting to avoid repeated alerts
                    self.potential_ip_scanners[ip] = set()
    
    def get_packet_rate(self):
        """Calculate current packet rate in packets per second."""
        if not self.packet_timestamps:
            return 0.0
        
        # Get timestamps from the last 5 seconds
        now = time.time()
        recent_timestamps = [ts for ts in self.packet_timestamps if now - ts <= 5]
        
        if not recent_timestamps:
            return 0.0
        
        # Calculate rate based on recent packets
        return len(recent_timestamps) / 5.0
    
    def get_bandwidth_stats(self):
        """Get current bandwidth statistics."""
        if not self.bandwidth_history:
            return {
                "current": 0,
                "average": 0,
                "peak": 0,
                "history": []
            }
        
        # Calculate statistics
        current = self.bandwidth_history[-1][1] if self.bandwidth_history else 0
        values = [bw for _, bw in self.bandwidth_history]
        average = sum(values) / len(values) if values else 0
        peak = max(values) if values else 0
        
        # Format history for plotting (last 30 seconds)
        history = list(self.bandwidth_history)[-30:]
        
        return {
            "current": current,
            "average": average,
            "peak": peak,
            "history": history
        }
    
    def get_protocol_distribution(self):
        """Get protocol distribution statistics."""
        total = sum(self.protocol_counts.values())
        if total == 0:
            return {}
        
        return {proto: count / total for proto, count in self.protocol_counts.items()}
    
    def set_filter(self, filter_expr):
        """Set a custom filter for packets."""
        try:
            # For simplicity, we'll just support basic filters on protocol names
            if filter_expr.lower() in ["tcp", "udp", "http", "dns", "smtp"]:
                proto = filter_expr.lower()
                self.packet_filter = lambda parsed: proto in parsed
            elif filter_expr.lower() == "all":
                self.packet_filter = lambda parsed: True
            elif filter_expr.startswith("ip:"):
                ip = filter_expr[3:].strip()
                self.packet_filter = lambda parsed: ("ip" in parsed and 
                                                  (parsed["ip"].headers["src"] == ip or 
                                                   parsed["ip"].headers["dst"] == ip))
            elif filter_expr.startswith("port:"):
                port = int(filter_expr[5:].strip())
                self.packet_filter = lambda parsed: (
                    ("tcp" in parsed and (parsed["tcp"].headers["sport"] == port or 
                                         parsed["tcp"].headers["dport"] == port)) or
                    ("udp" in parsed and (parsed["udp"].headers["sport"] == port or 
                                         parsed["udp"].headers["dport"] == port))
                )
            else:
                # Default to showing all
                self.packet_filter = lambda parsed: True
                
            return True
        except Exception as e:
            logger.error(f"Error setting filter: {e}")
            return False

    def format_size(self, size_bytes):
        """Format size in bytes to human-readable format."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def create_dashboard_layout() -> Layout:
    """Create the dashboard layout."""
    layout = Layout()
    
    # Split into main sections
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    
    # Split the body into panels
    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right")
    )
    
    # Split the left column
    layout["left"].split_column(
        Layout(name="traffic", ratio=3),
        Layout(name="bandwidth", ratio=2)
    )
    
    # Split the right column
    layout["right"].split_column(
        Layout(name="connections", ratio=2),
        Layout(name="alerts", ratio=3)
    )
    
    return layout


def update_header_panel(layout, monitor, refresh_interval, start_time):
    """Update the header panel with general information."""
    uptime = time.time() - start_time
    hours, remainder = divmod(int(uptime), 3600)
    minutes, seconds = divmod(remainder, 60)
    
    header_text = [
        f"[bold cyan]Network Protocol Analyzer[/bold cyan] - [green]Interface: {monitor.interface}[/green]",
        f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d} | Refresh: {refresh_interval:.1f}s | Total Packets: {monitor.total_packets} | Current Rate: {monitor.get_packet_rate():.1f} pkt/s"
    ]
    
    header_panel = Panel(
        "\n".join(header_text),
        title="Dashboard Status",
        border_style="blue"
    )
    
    layout["header"].update(header_panel)


def update_traffic_panel(layout, monitor):
    """Update the traffic statistics panel."""
    # Create protocol distribution table
    proto_table = Table(title="Protocol Distribution", box=box.SIMPLE)
    proto_table.add_column("Protocol", style="cyan")
    proto_table.add_column("Count", style="magenta")
    proto_table.add_column("Percentage", style="green")
    
    distribution = monitor.get_protocol_distribution()
    
    for proto, percentage in sorted(distribution.items(), key=lambda x: x[1], reverse=True):
        count = monitor.protocol_counts[proto]
        proto_table.add_row(
            proto.upper(),
            str(count),
            f"{percentage * 100:.1f}%"
        )
    
    # Top sources/destinations
    ip_table = Table(title="Top IP Addresses", box=box.SIMPLE)
    ip_table.add_column("Source IP", style="cyan")
    ip_table.add_column("Count", style="green")
    ip_table.add_column("Destination IP", style="cyan")
    ip_table.add_column("Count", style="green")
    
    # Get top 5 sources and destinations
    top_sources = monitor.ip_sources.most_common(5)
    top_dests = monitor.ip_destinations.most_common(5)
    
    # Ensure both lists are the same length by padding with empty values
    while len(top_sources) < 5:
        top_sources.append(("", ""))
    while len(top_dests) < 5:
        top_dests.append(("", ""))
    
    for (src, src_count), (dst, dst_count) in zip(top_sources, top_dests):
        ip_table.add_row(
            src,
            str(src_count) if src else "",
            dst,
            str(dst_count) if dst else ""
        )
    
    # Top ports
    port_table = Table(title="Top Ports", box=box.SIMPLE)
    port_table.add_column("TCP Port", style="cyan")
    port_table.add_column("Count", style="green")
    port_table.add_column("UDP Port", style="cyan")
    port_table.add_column("Count", style="green")
    
    # Get top 5 TCP and UDP ports
    top_tcp = monitor.tcp_ports.most_common(5)
    top_udp = monitor.udp_ports.most_common(5)
    
    # Ensure both lists are the same length
    while len(top_tcp) < 5:
        top_tcp.append(("", ""))
    while len(top_udp) < 5:
        top_udp.append(("", ""))
    
    for (tcp_port, tcp_count), (udp_port, udp_count) in zip(top_tcp, top_udp):
        port_table.add_row(
            str(tcp_port) if tcp_port else "",
            str(tcp_count) if tcp_port else "",
            str(udp_port) if udp_port else "",
            str(udp_count) if udp_port else ""
        )
    
    # Combine tables into a single panel
    traffic_panel = Panel(
        Columns([proto_table, ip_table, port_table], equal=True),
        title="Traffic Analysis",
        border_style="green"
    )
    
    layout["traffic"].update(traffic_panel)


def update_bandwidth_panel(layout, monitor):
    """Update the bandwidth panel with current bandwidth usage."""
    bw_stats = monitor.get_bandwidth_stats()
    
    # Format bandwidth values
    current_bw = monitor.format_size(bw_stats["current"])
    avg_bw = monitor.format_size(bw_stats["average"])
    peak_bw = monitor.format_size(bw_stats["peak"])
    
    # Create bandwidth text
    bw_text = Text()
    bw_text.append("\nCurrent: ", style="bold")
    bw_text.append(f"{current_bw}/s", style="cyan")
    bw_text.append(" | Average: ", style="bold")
    bw_text.append(f"{avg_bw}/s", style="green")
    bw_text.append(" | Peak: ", style="bold")
    bw_text.append(f"{peak_bw}/s", style="magenta")
    
    # Create a simple ASCII graph of bandwidth history
    if bw_stats["history"]:
        max_value = max(bw for _, bw in bw_stats["history"]) or 1
        graph_width = 50  # characters wide
        
        graph = "\n\n"
        for i, (ts, bw) in enumerate(bw_stats["history"]):
            # Skip every other point if we have too many
            if len(bw_stats["history"]) > graph_width and i % 2 == 1:
                continue
                
            # Normalize to graph height
            bar_height = int((bw / max_value) * 10)
            graph += "▇" * bar_height
            graph += " " * (10 - bar_height)
            graph += "\n"
    else:
        graph = "\n\nNo bandwidth data available yet."
    
    bw_panel = Panel(
        bw_text + graph,
        title="Bandwidth Usage",
        border_style="yellow"
    )
    
    layout["bandwidth"].update(bw_panel)


def update_connections_panel(layout, monitor):
    """Update the active connections panel."""
    conn_table = Table(title="Active Network Connections", box=box.SIMPLE)
    conn_table.add_column("Protocol", style="cyan")
    conn_table.add_column("Source", style="green")
    conn_table.add_column("Destination", style="green")
    conn_table.add_column("State", style="yellow")
    conn_table.add_column("Duration", style="magenta")
    conn_table.add_column("Bytes", style="blue")
    
    # Get the most active connections (by bytes) - limit to 10
    active_conns = sorted(
        monitor.active_connections.items(), 
        key=lambda x: x[1]["bytes"], 
        reverse=True
    )[:10]
    
    now = time.time()
    for (src_ip, src_port, dst_ip, dst_port), conn_info in active_conns:
        protocol = conn_info["protocol"]
        source = f"{src_ip}:{src_port}"
        destination = f"{dst_ip}:{dst_port}"
        state = conn_info["state"]
        
        # Calculate duration
        duration_secs = now - conn_info["start_time"]
        if duration_secs < 60:
            duration = f"{int(duration_secs)}s"
        elif duration_secs < 3600:
            duration = f"{int(duration_secs / 60)}m {int(duration_secs % 60)}s"
        else:
            duration = f"{int(duration_secs / 3600)}h {int((duration_secs % 3600) / 60)}m"
            
        # Format bytes
        bytes_str = monitor.format_size(conn_info["bytes"])
        
        # Determine row style based on state
        if state in ["CLOSING", "RESET"]:
            conn_table.add_row(protocol, source, destination, state, duration, bytes_str, style="dim")
        elif protocol == "TCP" and state == "ESTABLISHED":
            conn_table.add_row(protocol, source, destination, state, duration, bytes_str)
        else:
            conn_table.add_row(protocol, source, destination, state, duration, bytes_str)
    
    if not active_conns:
        conn_table.add_row("N/A", "N/A", "N/A", "N/A", "N/A", "N/A")
    
    conn_panel = Panel(
        conn_table,
        title=f"Active Connections ({len(monitor.active_connections)} total)",
        border_style="magenta"
    )
    
    layout["connections"].update(conn_panel)


def update_alerts_panel(layout, monitor):
    """Update the alerts panel with recent security alerts."""
    alerts_table = Table(title="Security Alerts", box=box.SIMPLE)
    alerts_table.add_column("Time", style="cyan", width=8)
    alerts_table.add_column("Level", style="magenta", width=8)
    alerts_table.add_column("Type", style="yellow", width=12)
    alerts_table.add_column("Message", style="green")
    
    for alert in reversed(list(monitor.alerts)):
        timestamp = datetime.fromtimestamp(alert["timestamp"]).strftime("%H:%M:%S")
        level = alert["level"]
        alert_type = alert["type"]
        message = alert["message"]
        
        # Use appropriate style based on level
        if level == "WARNING":
            alerts_table.add_row(timestamp, level, alert_type, message, style="yellow")
        elif level == "CRITICAL":
            alerts_table.add_row(timestamp, level, alert_type, message, style="red")
        else:
            alerts_table.add_row(timestamp, level, alert_type, message)
    
    if not monitor.alerts:
        alerts_table.add_row("N/A", "N/A", "N/A", "No alerts detected yet.")
    
    footer_text = (
        "\n[dim]Press 'q' to quit, 'f' to filter, 'c' to clear alerts[/dim]"
    )
    
    alerts_panel = Panel(
        Align.center(
            alerts_table,
            vertical="top"
        ) + Text(footer_text),
        title="Security Alerts & System Notifications",
        border_style="red"
    )
    
    layout["alerts"].update(alerts_panel)


def update_footer_panel(layout, monitor):
    """Update the footer panel with application status and command help."""
    footer_content = Text()
    footer_content.append("Commands: ", style="bold cyan")
    footer_content.append("q", style="bold green")
    footer_content.append(" - Quit | ", style="dim")
    footer_content.append("f", style="bold green")
    footer_content.append(" - Filter traffic | ", style="dim")
    footer_content.append("c", style="bold green")
    footer_content.append(" - Clear alerts | ", style="dim")
    footer_content.append("r", style="bold green")
    footer_content.append(" - Reset statistics", style="dim")
    
    footer_panel = Panel(
        footer_content,
        title="Command Reference",
        border_style="blue"
    )
    
    layout["footer"].update(footer_panel)


def handle_command(command, monitor):
    """Handle user commands.
    
    Args:
        command: The command entered by the user
        monitor: The network monitor instance
        
    Returns:
        Tuple of (should_exit, message)
    """
    if command.lower() == "q":
        return True, "Exiting..."
    
    elif command.lower() == "c":
        monitor.alerts.clear()
        return False, "Cleared all alerts."
    
    elif command.lower() == "r":
        with monitor.lock:
            monitor.total_packets = 0
            monitor.protocol_counts.clear()
            monitor.ip_sources.clear()
            monitor.ip_destinations.clear()
            monitor.tcp_ports.clear()
            monitor.udp_ports.clear()
            monitor.active_connections.clear()
            monitor.bandwidth_history.clear()
            monitor.traffic_history.clear()
            monitor.traffic_baseline = None
        return False, "Reset all statistics."
    
    elif command.lower().startswith("f "):
        filter_expr = command[2:].strip()
        if monitor.set_filter(filter_expr):
            return False, f"Applied filter: {filter_expr}"
        else:
            return False, f"Invalid filter: {filter_expr}"
    
    elif command.lower() == "f":
        # Interactive filter prompt
        return False, "Enter filter expression (e.g., 'tcp', 'ip:192.168.1.1', 'port:80', 'all')"
    
    else:
        return False, f"Unknown command: {command}"


def monitor_traffic(interface, refresh_interval=1.0, buffer_size=1000, bpf_filter="", alert_threshold=5):
    """Start monitoring network traffic with a live dashboard.
    
    Args:
        interface: Network interface to monitor
        refresh_interval: Dashboard refresh interval in seconds
        buffer_size: Number of packets to keep in buffer
        bpf_filter: BPF filter string to apply
        alert_threshold: Threshold for alerting on traffic spikes
    """
    # Initialize the network monitor
    monitor = RealTimeNetworkMonitor(
        interface=interface,
        buffer_size=buffer_size,
        alert_threshold=alert_threshold
    )
    
    # Set up signal handling
    def handle_signal(sig, frame):
        nonlocal should_exit
        logger.info("Received signal to exit")
        should_exit = True
    
    signal.signal(signal.SIGINT, handle_signal)
    
    # Set up dashboard layout
    layout = create_dashboard_layout()
    
    # Create command prompt
    command_prompt = ""
    command_message = ""
    waiting_for_input = False
    
    # Start capturing
    start_time = time.time()
    monitor.start_capture(bpf_filter)
    
    # Main update loop
    should_exit = False
    
    with Live(layout, refresh_per_second=1.0/refresh_interval, screen=True) as live:
        while not should_exit:
            try:
                # Update all panels
                update_header_panel(layout, monitor, refresh_interval, start_time)
                update_traffic_panel(layout, monitor)
                update_bandwidth_panel(layout, monitor)
                update_connections_panel(layout, monitor)
                update_alerts_panel(layout, monitor)
                update_footer_panel(layout, monitor)
                
                # Check if we need to display a command prompt
                if waiting_for_input:
                    # Pause the live display to get input
                    live.stop()
                    command = Prompt.ask(f"\n{command_message}")
                    live.start()
                    
                    should_exit, command_message = handle_command(command, monitor)
                    waiting_for_input = False
                
                # Check for keyboard input (non-blocking)
                # This is a simple approach; for more complex input handling,
                # you might want to use a library like prompt_toolkit
                if not waiting_for_input:
                    # Check if a key is available (non-blocking)
                    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                        key = sys.stdin.read(1)
                        if key:
                            if key == 'q':
                                should_exit = True
                            elif key == 'f':
                                waiting_for_input = True
                                command_message = "Enter filter (protocol, ip:x.x.x.x, port:N, all):"
                            elif key == 'c':
                                monitor.alerts.clear()
                            elif key == 'r':
                                with monitor.lock:
                                    monitor.total_packets = 0
                                    monitor.protocol_counts.clear()
                                    monitor.ip_sources.clear()
                                    monitor.ip_destinations.clear()
                                    monitor.tcp_ports.clear()
                                    monitor.udp_ports.clear()
                                    monitor.active_connections.clear()
                                    monitor.bandwidth_history.clear()
                                    monitor.traffic_history.clear()
                                    monitor.traffic_baseline = None
                
                time.sleep(refresh_interval)
                
            except Exception as e:
                logger.error(f"Error in dashboard update: {e}")
                time.sleep(refresh_interval)
    
    # Clean up
    monitor.stop_capture()
    logger.info("Network monitoring stopped")


def main():
    """Main function."""
    args = parse_arguments()
    
    try:
        # Display banner
        console.print(Panel.fit(
            "[bold cyan]Network Protocol Analyzer[/bold cyan]\n"
            "[green]Real-time Traffic Monitoring Dashboard[/green]",
            border_style="blue"
        ))
        console.print(f"Starting monitoring on interface [bold]{args.interface}[/bold]...\n")
        
        # Import select module for keyboard input
        global select
        import select
        
        # Set terminal to raw mode for keyboard input
        import tty
        import termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd, termios.TCSANOW)
            
            # Start monitoring
            monitor_traffic(
                interface=args.interface,
                refresh_interval=args.refresh_interval,
                buffer_size=args.buffer_size,
                bpf_filter=args.filter,
                alert_threshold=args.alert_threshold
            )
        finally:
            # Restore terminal settings
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
