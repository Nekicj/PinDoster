#!/usr/bin/env python3
"""
Tests for Traffic Analysis functionality.

This tests the real-time network monitoring, traffic pattern detection,
alert generation, and connection tracking features.
"""

import unittest
import pytest
from unittest.mock import MagicMock, patch, Mock
import os
import sys
import time
import threading
from collections import deque
import copy
from typing import Dict, Any, List, Tuple

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import from examples directory since it contains the RealTimeNetworkMonitor
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../examples')))

# Import the live_monitoring module (which contains RealTimeNetworkMonitor)
try:
    from examples.live_monitoring import RealTimeNetworkMonitor
except ImportError:
    # If direct import fails, try importing from examples subdirectory
    from live_monitoring import RealTimeNetworkMonitor


class TestRealTimeNetworkMonitor(unittest.TestCase):
    """Tests for RealTimeNetworkMonitor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a monitor instance with test parameters
        self.interface = "test_interface"
        self.buffer_size = 100
        self.alert_threshold = 3
        self.monitor = RealTimeNetworkMonitor(
            interface=self.interface,
            buffer_size=self.buffer_size,
            alert_threshold=self.alert_threshold
        )
        
        # Mock the actual sniffing to avoid real network operations
        self.original_sniff = scapy.sniff
        scapy.sniff = MagicMock()
        
        # Create test packets
        self.create_test_packets()
    
    def tearDown(self):
        """Clean up after tests."""
        # Restore original sniff function
        scapy.sniff = self.original_sniff
        
        # Stop the monitor if running
        if self.monitor.running:
            self.monitor.stop_capture()
    
    def create_test_packets(self):
        """Create test packets for various protocols and scenarios."""
        # Basic IP packets
        self.ip_packet1 = IP(src="192.168.1.1", dst="192.168.1.2")
        self.ip_packet2 = IP(src="192.168.1.2", dst="192.168.1.1")
        
        # TCP packets
        self.tcp_packet1 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80)
        self.tcp_packet2 = IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=80, dport=12345, flags="SA")
        
        # UDP packets
        self.udp_packet1 = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53)
        self.udp_packet2 = IP(src="192.168.1.2", dst="192.168.1.1") / UDP(sport=53, dport=12345)
        
        # ICMP packet
        self.icmp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / ICMP()
        
        # HTTP-like packet
        http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.http_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80) / http_payload
        
        # Packet for port scanning scenario
        self.port_scan_packets = []
        src_ip = "192.168.1.100"
        dst_ip = "192.168.1.200"
        for port in range(20, 30):
            self.port_scan_packets.append(
                IP(src=src_ip, dst=dst_ip) / TCP(sport=54321, dport=port, flags="S")
            )
        
        # Packets for IP scanning scenario
        self.ip_scan_packets = []
        src_ip = "192.168.1.100"
        for last_octet in range(1, 11):
            dst_ip = f"192.168.1.{last_octet}"
            self.ip_scan_packets.append(
                IP(src=src_ip, dst=dst_ip) / ICMP()
            )
    
    def test_initialization(self):
        """Test initialization and configuration."""
        # Check parameters were set correctly
        self.assertEqual(self.monitor.interface, self.interface)
        self.assertEqual(self.monitor.buffer_size, self.buffer_size)
        self.assertEqual(self.monitor.alert_threshold, self.alert_threshold)
        
        # Check that data structures were initialized
        self.assertIsInstance(self.monitor.packets, deque)
        self.assertEqual(self.monitor.packets.maxlen, self.buffer_size)
        self.assertIsInstance(self.monitor.protocol_counts, dict)
        self.assertIsInstance(self.monitor.active_connections, dict)
        self.assertIsInstance(self.monitor.alerts, deque)
    
    def test_start_stop_capture(self):
        """Test starting and stopping packet capture."""
        # Start capture
        self.monitor.start_capture()
        self.assertTrue(self.monitor.running)
        self.assertIsNotNone(self.monitor.sniffer_thread)
        self.assertIsNotNone(self.monitor.analyzer_thread)
        
        # Stop capture
        self.monitor.stop_capture()
        self.assertFalse(self.monitor.running)
    
    def test_process_packet(self):
        """Test packet processing and metrics."""
        # Process a TCP packet
        self.monitor._process_packet(self.tcp_packet1)
        
        # Check packet storage
        self.assertEqual(len(self.monitor.packets), 1)
        self.assertEqual(len(self.monitor.packet_timestamps), 1)
        
        # Check metrics
        self.assertEqual(self.monitor.total_packets, 1)
        self.assertGreater(self.monitor.bytes_received, 0)
        
        # Check protocol stats
        self.assertIn("ip", self.monitor.protocol_counts)
        self.assertIn("tcp", self.monitor.protocol_counts)
        self.assertEqual(self.monitor.protocol_counts["ip"], 1)
        self.assertEqual(self.monitor.protocol_counts["tcp"], 1)
        
        # Check IP tracking
        self.assertIn("192.168.1.1", self.monitor.ip_sources)
        self.assertIn("192.168.1.2", self.monitor.ip_destinations)
    
    def test_bandwidth_calculation(self):
        """Test bandwidth calculation."""
        # Mock time to control bandwidth calculation
        original_time = time.time
        
        try:
            # Set a fixed time
            current_time = 1000.0
            time.time = lambda: current_time
            
            # Set initial bandwidth update time
            self.monitor.last_bandwidth_update = current_time
            
            # First packet
            self.monitor.bytes_received = 0
            self.monitor._process_packet(self.tcp_packet1)
            packet_size = len(self.tcp_packet1)
            
            # Fast forward time
            current_time += self.monitor.bandwidth_update_interval
            time.time = lambda: current_time
            
            # Second packet - this should trigger bandwidth calculation
            self.monitor._process_packet(self.tcp_packet2)
            
            # Check bandwidth was calculated and history updated
            self.assertEqual(len(self.monitor.bandwidth_history), 1)
            
            # Get bandwidth stats
            bw_stats = self.monitor.get_bandwidth_stats()
            self.assertIn("current", bw_stats)
            self.assertIn("average", bw_stats)
            self.assertIn("peak", bw_stats)
            self.assertIn("history", bw_stats)
            
        finally:
            # Restore original time function
            time.time = original_time
    
    def test_connection_tracking(self):
        """Test connection tracking."""
        # Process TCP SYN packet to create a connection
        self.monitor._process_packet(self.tcp_packet1)
        
        # Check connection was created
        self.assertEqual(len(self.monitor.active_connections), 1)
        
        # Extract connection key
        conn_key = next(iter(self.monitor.active_connections.keys()))
        
        # Check connection details
        conn_info = self.monitor.active_connections[conn_key]
        self.assertIn("start_time", conn_info)
        self.assertIn("last_seen", conn_info)
        self.assertIn("packets", conn_info)
        self.assertIn("bytes", conn_info)
        self.assertIn("state", conn_info)
        self.assertIn("protocol", conn_info)
        
        # Check initial state
        self.assertEqual(conn_info["packets"], 1)
        self.assertEqual(conn_info["protocol"], "TCP")
        
        # Process a response packet for the same connection
        # This is a SYN-ACK response to the SYN
        self.monitor._process_packet(self.tcp_packet2)
        
        # Connection state should be updated (more packets, updated timestamp)
        self.assertEqual(conn_info["packets"], 2)
    
    def test_protocol_distribution(self):
        """Test protocol distribution calculation."""
        # Process multiple protocol packets
        self.monitor._process_packet(self.tcp_packet1)  # IP + TCP
        self.monitor._process_packet(self.udp_packet1)  # IP + UDP
        self.monitor._process_packet(self.icmp_packet)  # IP + ICMP
        self.monitor._process_packet(self.http_packet)  # IP + TCP + HTTP
        
        # Get distribution
        distribution = self.monitor.get_protocol_distribution()
        
        # Check distribution contains all protocols and sums to 1
        self.assertIn("ip", distribution)
        self.assertIn("tcp", distribution)
        self.assertIn("udp", distribution)
        self.assertIn("icmp", distribution)
        self.assertIn("http", distribution)
        
        # Sum should be close to 1 (accounting for floating point precision)
        total = sum(distribution.values())
        self.assertAlmostEqual(total, 1.0)
        
        # Check counts
        self.assertEqual(self.monitor.protocol_counts["ip"], 4)  # All packets have IP
        self.assertEqual(self.monitor.protocol_counts["tcp"], 2)  # TCP and HTTP packets
        self.assertEqual(self.monitor.protocol_counts["udp"], 1)
        self.assertEqual(self.monitor.protocol_counts["icmp"], 1)
        self.assertEqual(self.monitor.protocol_counts["http"], 1)
    
    def test_expired_connection_cleanup(self):
        """Test cleanup of expired connections."""
        # Process a packet to create a connection
        self.monitor._process_packet(self.tcp_packet1)
        
        # Check connection was created
        self.assertEqual(len(self.monitor.active_connections), 1)
        
        # Mock time for testing
        original_time = time.time
        
        try:
            # Set initial time
            current_time = 1000.0
            time.time = lambda: current_time
            
            # Set the connection's last_seen time to now
            conn_key = next(iter(self.monitor.active_connections.keys()))
            self.monitor.active_connections[conn_key]["last_seen"] = current_time
            
            # Fast forward time past the connection timeout
            current_time += self.monitor.connection_timeout + 10
            time.time = lambda: current_time
            
            # Run connection cleanup
            self.monitor._cleanup_expired_connections()
            
            # Connection should be removed
            self.assertEqual(len(self.monitor.active_connections), 0)
            
        finally:
            # Restore original time function
            time.time = original_time
    
    def test_port_scan_detection(self):
        """Test port scanning detection."""
        # Use a controlled time for testing
        original_time = time.time
        current_time = 1000.0
        
        try:
            # Setup time function to return our controlled time
            time.time = lambda: current_time
            
            # Reduce threshold for testing
            self.monitor.port_scan_threshold = 5  # Detect after 5 unique ports
            
            # Process packets that simulate port scanning (same src to multiple ports)
            for i, packet in enumerate(self.port_scan_packets[:6]):  # Just over the threshold
                # Update timestamp (all within window)
                self.monitor.packet_timestamps.append(current_time)
                
                # Process the packet
                self.monitor._process_packet(packet)
            
            # Run scan detection
            self.monitor._detect_scanning()
            
            # Should have generated a port scan alert
            port_scan_alerts = [a for a in self.monitor.alerts if a["type"] == "PORT_SCAN"]
            self.assertGreaterEqual(len(port_scan_alerts), 1)
            
            # Check alert details
            alert = port_scan_alerts[0]
            self.assertEqual(alert["level"], "WARNING")
            self.assertIn("192.168.1.100", alert["message"])  # Scanner IP should be in message
            
        finally:
            # Restore original time function
            time.time = original_time
    
    def test_ip_scan_detection(self):
        """Test IP scanning detection."""
        # Use a controlled time for testing
        original_time = time.time
        current_time = 1000.0
        
        try:
            # Setup time function to return our controlled time
            time.time = lambda: current_time
            
            # Reduce threshold for testing
            self.monitor.ip_scan_threshold = 5  # Detect after 5 unique IPs
            
            # Process packets that simulate IP scanning (same src to multiple targets)
            for i, packet in enumerate(self.ip_scan_packets[:6]):  # Just over the threshold
                # Update timestamp (all within window)
                self.monitor.packet_timestamps.append(current_time)
                
                # Process the packet
                self.monitor._process_packet(packet)
            
            # Run scan detection
            self.monitor._detect_scanning()
            
            # Should have generated an IP scan alert
            ip_scan_alerts = [a for a in self.monitor.alerts if a["type"] == "IP_SCAN"]
            self.assertGreaterEqual(len(ip_scan_alerts), 1)
            
            # Check alert details
            alert = ip_scan_alerts[0]
            self.assertEqual(alert["level"], "WARNING")
            self.assertIn("192.168.1.100", alert["message"])  # Scanner IP should be in message
            
        finally:
            # Restore original time function
            time.time = original_time
    
    def test_traffic_anomalies(self):
        """Test traffic anomaly detection (spikes and drops)."""
        # Use a controlled time for testing
        original_time = time.time
        current_time = 1000.0
        
        try:
            # Setup time function to return our controlled time
            time.time = lambda: current_time
            
            # Set up initial traffic history to establish a baseline
            # First establish a stable baseline of 1 packet per second for 20 seconds
            for i in range(20):
                current_time += 1.0
                self.monitor.traffic_history.append((current_time, 1))  # 1 packet per second
            
            # Calculate baseline
            self.monitor._detect_traffic_anomalies()
            self.assertIsNotNone(self.monitor.traffic_baseline)
            self.assertAlmostEqual(self.monitor.traffic_baseline, 1.0, delta=0.3)  # Close to 1 pkt/sec
            
            # Now simulate a traffic spike (5x the baseline)
            current_time += 1.0
            for i in range(25):  # 25 packets in 5 seconds (5 pkt/sec)
                self.monitor.traffic_history.append((current_time + (i % 5) * 0.2, 1))
            
            # Detect the spike
            self.monitor.alerts.clear()  # Clear any previous alerts
            self.monitor._detect_traffic_anomalies()
            
            # Should have a traffic spike alert
            spike_alerts = [a for a in self.monitor.alerts if a["type"] == "TRAFFIC_SPIKE"]
            self.assertGreaterEqual(len(spike_alerts), 1)
            
            # Check alert details
            alert = spike_alerts[0]
            self.assertEqual(alert["level"], "WARNING")
            self.assertIn("spike", alert["message"].lower())
            
            # Now simulate a traffic drop (80% reduction from baseline)
            self.monitor.alerts.clear()  # Clear previous alerts
            
            # No traffic for 5 seconds
            current_time += 10.0  # Fast forward
            
            # Just one packet in 5 seconds
            self.monitor.traffic_history.append((current_time, 1))
            
            # Detect the drop
            self.monitor._detect_traffic_anomalies()
            
            # Should have a traffic drop alert
            drop_alerts = [a for a in self.monitor.alerts if a["type"] == "TRAFFIC_DROP"]
            self.assertGreaterEqual(len(drop_alerts), 1)
            
            # Check alert details
            alert = drop_alerts[0]
            self.assertEqual(alert["level"], "INFO")
            self.assertIn("drop", alert["message"].lower())
            
        finally:
            # Restore original time function
            time.time = original_time
    
    def test_packet_rate(self):
        """Test packet rate calculation."""
        # Use a controlled time for testing
        original_time = time.time
        current_time = 1000.0
        
        try:
            # Setup time function to return our controlled time
            time.time = lambda: current_time
            
            # Empty packet history should return 0 rate
            self.monitor.packet_timestamps.clear()
            self.assertEqual(self.monitor.get_packet_rate(), 0.0)
            
            # Add 5 packets in the last 5 seconds
            for i in range(5):
                self.monitor.packet_timestamps.append(current_time - i * 0.5)  # 0.5 second intervals
            
            # Rate should be 1 packet per second
            self.assertAlmostEqual(self.monitor.get_packet_rate(), 1.0, delta=0.1)
            
            # Add 10 more packets in the last second (burst)
            for i in range(10):
                self.monitor.packet_timestamps.append(current_time - 0.1)  # All very recent
            
            # Rate should now be 3 packets per second (15 packets in 5 seconds)
            self.assertAlmostEqual(self.monitor.get_packet_rate(), 3.0, delta=0.1)
            
            # Test with packets older than the 5-second window
            self.monitor.packet_timestamps.clear()
            for i in range(5):
                self.monitor.packet_timestamps.append(current_time - 10.0)  # All 10 seconds old
            
            # Should return 0 as all packets are outside the recent window
            self.assertEqual(self.monitor.get_packet_rate(), 0.0)
            
        finally:
            # Restore original time function
            time.time = original_time
    
    def test_filter_functionality(self):
        """Test packet filtering functionality."""
        # Create a filter for TCP protocol
        self.assertTrue(self.monitor.set_filter("tcp"))
        
        # Create a parsed packet mock with TCP
        tcp_parsed = {"tcp": True, "ip": True}
        udp_parsed = {"udp": True, "ip": True}
        
        # TCP packet should pass the filter
        self.assertTrue(self.monitor.packet_filter(tcp_parsed))
        
        # UDP packet should not pass the filter
        self.assertFalse(self.monitor.packet_filter(udp_parsed))
        
        # Reset filter to "all"
        self.assertTrue(self.monitor.set_filter("all"))
        
        # Now both should pass
        self.assertTrue(self.monitor.packet_filter(tcp_parsed))
        self.assertTrue(self.monitor.packet_filter(udp_parsed))
        
        # Test IP-specific filter
        self.assertTrue(self.monitor.set_filter("ip:192.168.1.1"))
        
        # Create parsed packet mocks with different IPs
        matching_ip = {"ip": {"headers": {"src": "192.168.1.1", "dst": "192.168.1.2"}}}
        non_matching_ip = {"ip": {"headers": {"src": "10.0.0.1", "dst": "10.0.0.2"}}}
        
        # Matching IP should pass
        self.assertTrue(self.monitor.packet_filter(matching_ip))
        
        # Non-matching IP should not pass
        self.assertFalse(self.monitor.packet_filter(non_matching_ip))
        
        # Test invalid filter
        with patch('logging.Logger.error') as mock_log:
            self.assertFalse(self.monitor.set_filter("invalid:filter"))
            mock_log.assert_called()  # Should log an error
    
    def test_alert_system(self):
        """Test alert system functionality."""
        # Check alert storage
        self.assertIsInstance(self.monitor.alerts, deque)
        
        # Add a test alert
        test_alert = {
            "timestamp": time.time(),
            "type": "TEST_ALERT",
            "message": "This is a test alert",
            "level": "INFO"
        }
        self.monitor.alerts.append(test_alert)
        
        # Check alert was added
        self.assertEqual(len(self.monitor.alerts), 1)
        self.assertEqual(self.monitor.alerts[0]["type"], "TEST_ALERT")
        
        # Test alert limit (should be capped at maxlen)
        original_maxlen = self.monitor.alerts.maxlen
        
        # Set a small maxlen for testing
        test_maxlen = 5
        self.monitor.alerts = deque(maxlen=test_maxlen)
        
        # Add more alerts than the limit
        for i in range(test_maxlen + 5):
            self.monitor.alerts.append({
                "timestamp": time.time(),
                "type": f"ALERT_{i}",
                "message": f"Test alert {i}",
                "level": "INFO"
            })
        
        # Should be limited to maxlen
        self.assertEqual(len(self.monitor.alerts), test_maxlen)
        
        # First alerts should be discarded, only last maxlen should remain
        alert_types = [a["type"] for a in self.monitor.alerts]
        for i in range(test_maxlen + 5 - test_maxlen, test_maxlen + 5):
            self.assertIn(f"ALERT_{i}", alert_types)
        
        # Reset maxlen
        self.monitor.alerts = deque(maxlen=original_maxlen)
        
        # Test alert generation through detect methods
        # Set up for port scan detection
        self.monitor.port_scan_threshold = 3
        self.monitor.alerts.clear()
        self.monitor.packet_timestamps = deque(maxlen=self.buffer_size)
        
        # Add packets for potential port scan
        current_time = time.time()
        self.monitor.packet_timestamps.append(current_time)
        
        # Create scan activity
        ip = "192.168.1.100"
        self.monitor.potential_scanners[ip] = set([80, 443, 8080])  # 3 unique ports
        self.monitor.ip_sources[ip] = 3  # Add to sources
        
        # Run detection
        self.monitor._detect_scanning()
        
        # Should generate a PORT_SCAN alert
        self.assertGreaterEqual(len(self.monitor.alerts), 1)
        self.assertEqual(self.monitor.alerts[0]["type"], "PORT_SCAN")
        
        # Verify reset after alert
        self.assertEqual(len(self.monitor.potential_scanners[ip]), 0)  # Should be reset


if __name__ == "__main__":
    unittest.main()
