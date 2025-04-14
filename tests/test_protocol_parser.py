#!/usr/bin/env python3
"""
Tests for the Protocol Parser core functionality.

This includes tests for:
- Protocol detection
- Protocol parsing
- Deep packet inspection
- Protocol fingerprinting
"""

import unittest
import pytest
from unittest.mock import MagicMock, patch
import os
import sys
import time
from typing import Dict, Any, List, Tuple

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.protocol_parser.parser import (
    ProtocolParser, ProtocolInfo, ProtocolFingerprint,
    IPHandler, TCPHandler, UDPHandler, ICMPHandler,
    HTTPHandler, DNSHandler, SMTPHandler
)


class TestProtocolDetection(unittest.TestCase):
    """Tests for protocol detection functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = ProtocolParser()
        
        # Create sample packets
        self.ip_packet = IP(src="192.168.1.1", dst="192.168.1.2")
        self.tcp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80)
        self.udp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53)
        self.icmp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / ICMP()
        
        # Create HTTP-like packet
        http_payload = (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"\r\n"
        )
        self.http_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80) / http_payload
        
        # Create DNS-like packet
        self.dns_packet = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53) / DNS()
        
        # Create SMTP-like packet
        smtp_payload = b"EHLO example.com\r\n"
        self.smtp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=25) / smtp_payload
    
    def test_has_protocol_ip(self):
        """Test detection of IP protocol."""
        self.assertTrue(self.parser._has_protocol(self.ip_packet, "ip"))
        self.assertTrue(self.parser._has_protocol(self.tcp_packet, "ip"))
        self.assertTrue(self.parser._has_protocol(self.udp_packet, "ip"))
        self.assertTrue(self.parser._has_protocol(self.icmp_packet, "ip"))
    
    def test_has_protocol_tcp(self):
        """Test detection of TCP protocol."""
        self.assertFalse(self.parser._has_protocol(self.ip_packet, "tcp"))
        self.assertTrue(self.parser._has_protocol(self.tcp_packet, "tcp"))
        self.assertFalse(self.parser._has_protocol(self.udp_packet, "tcp"))
        self.assertFalse(self.parser._has_protocol(self.icmp_packet, "tcp"))
    
    def test_has_protocol_udp(self):
        """Test detection of UDP protocol."""
        self.assertFalse(self.parser._has_protocol(self.ip_packet, "udp"))
        self.assertFalse(self.parser._has_protocol(self.tcp_packet, "udp"))
        self.assertTrue(self.parser._has_protocol(self.udp_packet, "udp"))
        self.assertFalse(self.parser._has_protocol(self.icmp_packet, "udp"))
    
    def test_has_protocol_icmp(self):
        """Test detection of ICMP protocol."""
        self.assertFalse(self.parser._has_protocol(self.ip_packet, "icmp"))
        self.assertFalse(self.parser._has_protocol(self.tcp_packet, "icmp"))
        self.assertFalse(self.parser._has_protocol(self.udp_packet, "icmp"))
        self.assertTrue(self.parser._has_protocol(self.icmp_packet, "icmp"))
    
    def test_has_protocol_http(self):
        """Test detection of HTTP protocol."""
        self.assertFalse(self.parser._has_protocol(self.ip_packet, "http"))
        self.assertFalse(self.parser._has_protocol(self.tcp_packet, "http"))
        self.assertTrue(self.parser._has_protocol(self.http_packet, "http"))
        self.assertFalse(self.parser._has_protocol(self.dns_packet, "http"))
    
    def test_has_protocol_dns(self):
        """Test detection of DNS protocol."""
        self.assertFalse(self.parser._has_protocol(self.ip_packet, "dns"))
        self.assertFalse(self.parser._has_protocol(self.tcp_packet, "dns"))
        self.assertTrue(self.parser._has_protocol(self.dns_packet, "dns"))
        self.assertFalse(self.parser._has_protocol(self.http_packet, "dns"))
    
    def test_has_protocol_smtp(self):
        """Test detection of SMTP protocol."""
        self.assertFalse(self.parser._has_protocol(self.ip_packet, "smtp"))
        self.assertFalse(self.parser._has_protocol(self.tcp_packet, "smtp"))
        self.assertTrue(self.parser._has_protocol(self.smtp_packet, "smtp"))
        self.assertFalse(self.parser._has_protocol(self.http_packet, "smtp"))


class TestProtocolParsing(unittest.TestCase):
    """Tests for protocol parsing functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = ProtocolParser()
        
        # Create sample packets
        self.ip_packet = IP(src="192.168.1.1", dst="192.168.1.2")
        self.tcp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80)
        self.udp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53)
        self.icmp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / ICMP()
        
        # Create HTTP-like packet
        http_payload = (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"\r\n"
        )
        self.http_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80) / http_payload
        
        # Create DNS packet with query
        self.dns_packet = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53) / DNS(
            qd=scapy.DNSQR(qname="example.com")
        )
        
        # Create SMTP-like packet
        smtp_payload = b"EHLO example.com\r\n"
        self.smtp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=25) / smtp_payload
    
    def test_parse_ip(self):
        """Test parsing of IP protocol."""
        result = self.parser._parse_ip(self.ip_packet)
        self.assertEqual(result.name, "ip")
        self.assertEqual(result.version, "IPv4")
        self.assertEqual(result.headers["src"], "192.168.1.1")
        self.assertEqual(result.headers["dst"], "192.168.1.2")
        
    def test_parse_tcp(self):
        """Test parsing of TCP protocol."""
        result = self.parser._parse_tcp(self.tcp_packet)
        self.assertEqual(result.name, "tcp")
        self.assertEqual(result.headers["sport"], 12345)
        self.assertEqual(result.headers["dport"], 80)
        
    def test_parse_udp(self):
        """Test parsing of UDP protocol."""
        result = self.parser._parse_udp(self.udp_packet)
        self.assertEqual(result.name, "udp")
        self.assertEqual(result.headers["sport"], 12345)
        self.assertEqual(result.headers["dport"], 53)
        
    def test_parse_icmp(self):
        """Test parsing of ICMP protocol."""
        result = self.parser._parse_icmp(self.icmp_packet)
        self.assertEqual(result.name, "icmp")
        self.assertIn("type", result.headers)
        self.assertIn("code", result.headers)
        
    def test_parse_http(self):
        """Test parsing of HTTP protocol."""
        result = self.parser._parse_http(self.http_packet)
        self.assertEqual(result.name, "http")
        self.assertTrue(result.metadata["is_request"])
        self.assertEqual(result.headers["method"], "GET")
        self.assertEqual(result.headers["path"], "/index.html")
        self.assertEqual(result.headers["Host"], "example.com")
        
    def test_parse_dns(self):
        """Test parsing of DNS protocol."""
        result = self.parser._parse_dns(self.dns_packet)
        self.assertEqual(result.name, "dns")
        self.assertEqual(len(result.headers["queries"]), 1)
        self.assertEqual(result.headers["queries"][0]["name"], "example.com.")
        
    def test_parse_smtp(self):
        """Test parsing of SMTP protocol."""
        result = self.parser._parse_smtp(self.smtp_packet)
        self.assertEqual(result.name, "smtp")
        self.assertTrue(result.metadata["is_command"])
        self.assertEqual(result.headers["command"], "EHLO")
        self.assertEqual(result.headers["parameter"], "example.com")


class TestDeepPacketInspection(unittest.TestCase):
    """Tests for deep packet inspection functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = ProtocolParser()
        
        # Create sample packets
        self.tcp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
            sport=12345, dport=80, flags="PA", window=8192, options=[('MSS', 1460)]
        )
        
        # Create HTTP packet
        http_payload = (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Cookie: session=abc123; secure; httponly\r\n"
            b"\r\n"
            b"<!DOCTYPE html><html><head><meta name=\"description\" content=\"Test page\"></head></html>"
        )
        self.http_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80) / http_payload
        
        # Create DNS packet with query
        self.dns_packet = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53) / DNS(
            qd=scapy.DNSQR(qname="example.com")
        )
        
        # Create SMTP packet
        smtp_payload = (
            b"MAIL FROM:<user@example.com>\r\n"
        )
        self.smtp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=25) / smtp_payload
    
    def test_dpi_tcp(self):
        """Test deep packet inspection for TCP."""
        results = self.parser.parse_packet(self.tcp_packet)
        self.assertIn("tcp", results)
        self.assertIn("dpi_results", results["tcp"].__dict__)
        
        # Check specific DPI results
        dpi = results["tcp"].dpi_results
        self.assertIn("flags_detailed", dpi)
        self.assertIn("window", dpi)
        self.assertIn("options", dpi)
        self.assertIn("connections_states", dpi)
        
        # Verify the TCP flags are correctly decoded
        self.assertTrue(dpi["flags_detailed"]["psh"])
        self.assertTrue(dpi["flags_detailed"]["ack"])
    
    def test_dpi_http(self):
        """Test deep packet inspection for HTTP."""
        results = self.parser.parse_packet(self.http_packet)
        self.assertIn("http", results)
        self.assertIn("dpi_results", results["http"].__dict__)
        
        # Check HTTP-specific DPI results
        dpi = results["http"].dpi_results
        
        # Check for content analysis
        self.assertIn("content_analysis", dpi)
        
        # Check for security analysis of cookies
        self.assertIn("security", dpi)
        self.assertTrue(dpi["security"]["secure_cookie"])
        self.assertTrue(dpi["security"]["httponly_cookie"])
    
    def test_dpi_dns(self):
        """Test deep packet inspection for DNS."""
        # Create a more complex DNS packet with authority and additional sections
        dns_packet = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53) / DNS(
            qd=scapy.DNSQR(qname="verylongdomainnamefortest.example.com" * 5)  # Very long name for testing tunneling detection
        )
        
        results = self.parser.parse_packet(dns_packet)
        self.assertIn("dns", results)
        
        # Check for suspicious long domain name detection
        dpi = results["dns"].dpi_results
        self.assertIn("suspicious", dpi)
        self.assertTrue(dpi["suspicious"])
    
    def test_dpi_smtp(self):
        """Test deep packet inspection for SMTP."""
        # Create a more complex SMTP packet with email data
        smtp_payload = (
            b"MAIL FROM:<user@example.com>\r\n"
            b"RCPT TO:<recipient@example.org>\r\n"
            b"DATA\r\n"
            b"From: User <user@example.com>\r\n"
            b"To: Recipient <recipient@example.org>\r\n"
            b"Subject: Test Email\r\n"
            b"Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n"
            b"\r\n"
            b"--boundary123\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"This is a test email with an attachment.\r\n"
            b"--boundary123\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=\"test.txt\"\r\n"
            b"\r\n"
            b"Test attachment content\r\n"
            b"--boundary123--\r\n"
            b".\r\n"
        )
        smtp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=25) / smtp_payload
        
        results = self.parser.parse_packet(smtp_packet)
        self.assertIn("smtp", results)
        
        # Check SMTP-specific DPI results
        dpi = results["smtp"].dpi_results
        
        # Check for email address extraction
        self.assertIn("email_addresses", dpi)
        self.assertIn("user@example.com", dpi["email_addresses"])
        self.assertIn("recipient@example.org", dpi["email_addresses"])
        
        # Check for attachment detection
        self.assertIn("has_attachment", dpi)
        self.assertTrue(dpi["has_attachment"])
        
        # Check for multipart detection
        self.assertIn("is_multipart", dpi)
        self.assertTrue(dpi["is_multipart"])
        
        # Check for boundary detection
        self.assertIn("boundary", dpi)
        self.assertEqual(dpi["boundary"], "boundary123")


class TestProtocolFingerprinting(unittest.TestCase):
    """Tests for protocol fingerprinting functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = ProtocolParser()
        self.fingerprinter = ProtocolFingerprint()
        
        # Create ambiguous packets (without standard port or clear protocol markers)
        
        # HTTP-like packet on non-standard port
        http_payload = (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"\r\n"
        )
        self.http_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=8888) / http_payload
        
        # SMTP-like packet on non-standard port
        smtp_payload = b"EHLO example.com\r\n"
        self.smtp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=9999) / smtp_payload
        
        # FTP-like packet
        ftp_payload = b"USER anonymous\r\n"
        self.ftp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=8888) / ftp_payload
        
        # SSH-like packet
        ssh_payload = b"SSH-2.0-OpenSSH_7.4\r\n"
        self.ssh_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=8888) / ssh_payload
        
        # Packet with no clear protocol signatures
        random_payload = b"This is just some random data with no clear protocol markers."
        self.random_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=8888) / random_payload
    
    def test_identify_protocol_http(self):
        """Test fingerprinting HTTP protocol."""
        # Extract the payload from the packet
        payload = bytes(self.http_packet[TCP].payload)
        
        # Identify the protocol
        results = self.fingerprinter.identify_protocol(payload)
        
        # Verify HTTP is identified with high confidence
        self.assertTrue(results)  # Ensure we got results
        self.assertEqual(results[0][0], "http")  # First match should be HTTP
        self.assertGreater(results[0][1], 0.8)  # High confidence
    
    def test_identify_protocol_smtp(self):
        """Test fingerprinting SMTP protocol."""
        # Extract the payload from the packet
        payload = bytes(self.smtp_packet[TCP].payload)
        
        # Identify the protocol
        results = self.fingerprinter.identify_protocol(payload)
        
        # Verify SMTP is identified
        self.assertTrue(results)
        self.assertEqual(results[0][0], "smtp")
        self.assertGreater(results[0][1], 0.7)
    
    def test_identify_protocol_ftp(self):
        """Test fingerprinting FTP protocol."""
        # Extract the payload from the packet
        payload = bytes(self.ftp_packet[TCP].payload)
        
        # Identify the protocol
        results = self.fingerprinter.identify_protocol(payload)
        
        # Verify FTP is identified
        self.assertTrue(results)
        self.assertEqual(results[0][0], "ftp")
        self.assertGreater(results[0][1], 0.7)
    
    def test_identify_protocol_ssh(self):
        """Test fingerprinting SSH protocol."""
        # Extract the payload from the packet
        payload = bytes(self.ssh_packet[TCP].payload)
        
        # Identify the protocol
        results = self.fingerprinter.identify_protocol(payload)
        
        # Verify SSH is identified
        self.assertTrue(results)
        self.assertEqual(results[0][0], "ssh")
        self.assertGreater(results[0][1], 0.7)
    
    def test_identify_protocol_unknown(self):
        """Test fingerprinting unknown protocol."""
        # Extract the payload from the packet
        payload = bytes(self.random_packet[TCP].payload)
        
        # Identify the protocol
        results = self.fingerprinter.identify_protocol(payload)
        
        # Verify no clear match or very low confidence
        if results:
            self.assertLess(results[0][1], 0.7)  # Low confidence if any match
    
    def test_packet_fingerprinting_integration(self):
        """Test the integration of fingerprinting with packet parsing."""
        # Process packets with the parser which should perform fingerprinting
        http_results = self.parser.fingerprint_packet(self.http_packet)
        smtp_results = self.parser.fingerprint_packet(self.smtp_packet)
        
        # Verify both methods successfully fingerprinted the protocols
        self.assertTrue(http_results)
        self.assertEqual(http_results[0][0], "http")
        
        self.assertTrue(smtp_results)
        self.assertEqual(smtp_results[0][0], "smtp")


class TestEdgeCases(unittest.TestCase):
    """Tests for handling edge cases in protocol parsing."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = ProtocolParser()
        
        # Create edge case packets
        
        # Malformed HTTP packet
        malformed_http = (
            b"GET /index.html\r\n"  # Missing HTTP version
            b"Host: example.com\r\n"
            b"\r\n"
        )
        self.malformed_http_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80) / malformed_http
        
        # Truncated TCP packet
        self.truncated_tcp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80)
        # Manually corrupt the packet length to simulate truncation
        self.truncated_tcp_packet.len = 20  # Unrealistically small IP length
        
        # Empty payload
        self.empty_payload_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80) / b""
        
        # Fragmented IP packet
        self.frag_packet = IP(src="192.168.1.1", dst="192.168.1.2", flags=1, frag=0)  # More fragments flag set
        
        # Very large packet
        large_payload = b"X" * 9000  # Much larger than typical MTU
        self.large_packet = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53) / large_payload
    
    def test_malformed_http(self):
        """Test parsing of malformed HTTP packet."""
        try:
            results = self.parser.parse_packet(self.malformed_http_packet)
            
            # It should still recognize it's a HTTP packet
            self.assertIn("http", results)
            
            # But the parsing might be incomplete
            http_info = results["http"]
            self.assertIn("headers", http_info.__dict__)
            
            # It may not have recognized the version
            self.assertIsNone(http_info.version)
            
        except Exception as e:
            self.fail(f"Parser failed on malformed HTTP with exception: {e}")
    
    def test_empty_payload(self):
        """Test parsing of packet with empty payload."""
        try:
            results = self.parser.parse_packet(self.empty_payload_packet)
            
            # Should parse IP and TCP but not any application layer
            self.assertIn("ip", results)
            self.assertIn("tcp", results)
            self.assertNotIn("http", results)
            
        except Exception as e:
            self.fail(f"Parser failed on empty payload with exception: {e}")
    
    def test_large_packet(self):
        """Test parsing of unusually large packet."""
        try:
            results = self.parser.parse_packet(self.large_packet)
            
            # Should parse IP and UDP
            self.assertIn("ip", results)
            self.assertIn("udp", results)
            
            # UDP should have the large payload
            self.assertEqual(len(results["udp"].data), 9000)
            
        except Exception as e:
            self.fail(f"Parser failed on large packet with exception: {e}")
            
    def test_fragmented_packet(self):
        """Test parsing of fragmented IP packet."""
        try:
            results = self.parser.parse_packet(self.frag_packet)
            
            # Should parse IP
            self.assertIn("ip", results)
            
            # Deep inspection should note the fragmentation
            self.assertTrue(results["ip"].dpi_results["flags"] & 1)  # More fragments flag
            
        except Exception as e:
            self.fail(f"Parser failed on fragmented packet with exception: {e}")


if __name__ == "__main__":
    unittest.main()
