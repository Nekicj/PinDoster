#!/usr/bin/env python3
"""
Tests for Protocol Handler functionality.

This tests individual protocol handlers for correct parsing, deep inspection,
and protocol-specific features.
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
from scapy.layers.dns import DNS, DNSQR, DNSRR

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.protocol_parser.parser import (
    ProtocolInfo,
    IPHandler, TCPHandler, UDPHandler, ICMPHandler,
    HTTPHandler, DNSHandler, SMTPHandler
)


class TestIPHandler(unittest.TestCase):
    """Tests for IPHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.handler = IPHandler()
        
        # Create sample packets
        self.ip_packet = IP(src="192.168.1.1", dst="192.168.1.2", ttl=64, id=12345)
        self.ip_packet_frag = IP(src="192.168.1.1", dst="192.168.1.2", flags=1, frag=100)  # Fragmented
        self.tcp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
        self.non_ip_packet = scapy.Ether() / scapy.ARP()
    
    def test_protocol_name(self):
        """Test protocol name."""
        self.assertEqual(self.handler.protocol_name, "ip")
    
    def test_can_handle(self):
        """Test can_handle method."""
        self.assertTrue(self.handler.can_handle(self.ip_packet))
        self.assertTrue(self.handler.can_handle(self.tcp_packet))
        self.assertFalse(self.handler.can_handle(self.non_ip_packet))
    
    def test_parse(self):
        """Test parse method."""
        result = self.handler.parse(self.ip_packet)
        
        # Check basic IP fields
        self.assertEqual(result.name, "ip")
        self.assertEqual(result.version, "IPv4")
        self.assertEqual(result.headers["src"], "192.168.1.1")
        self.assertEqual(result.headers["dst"], "192.168.1.2")
        self.assertEqual(result.headers["ttl"], 64)
        self.assertEqual(result.headers["id"], 12345)
        
        # Check metadata
        self.assertIn("length", result.metadata)
        self.assertIn("timestamp", result.metadata)
    
    def test_deep_inspect(self):
        """Test deep_inspect method."""
        info = self.handler.parse(self.ip_packet_frag)
        self.handler.deep_inspect(self.ip_packet_frag, info)
        
        # Check DPI results
        self.assertIn("flags", info.dpi_results)
        self.assertIn("frag", info.dpi_results)
        self.assertIn("tos", info.dpi_results)
        self.assertIn("options", info.dpi_results)
        
        # Check fragmentation
        self.assertEqual(info.dpi_results["frag"], 100)
        self.assertEqual(info.dpi_results["flags"], 1)  # More fragments flag
    
    def test_error_handling(self):
        """Test error handling for invalid packets."""
        # Create an invalid packet (no IP layer)
        invalid_packet = scapy.Ether()
        
        # Should raise a specific exception
        with self.assertRaises(Exception):
            self.handler.parse(invalid_packet)


class TestTCPHandler(unittest.TestCase):
    """Tests for TCPHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.handler = TCPHandler()
        
        # Create sample packets
        self.tcp_syn_packet = IP() / TCP(sport=12345, dport=80, flags="S", seq=1000, ack=0)
        self.tcp_synack_packet = IP() / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
        self.tcp_psh_packet = IP() / TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001, window=8192)
        self.tcp_rst_packet = IP() / TCP(sport=12345, dport=80, flags="R", seq=1001, ack=2001)
        self.tcp_options_packet = IP() / TCP(options=[('MSS', 1460), ('SAckOK', b''), ('Timestamp', (123456789, 0))])
        self.non_tcp_packet = IP() / UDP()
    
    def test_protocol_name(self):
        """Test protocol name."""
        self.assertEqual(self.handler.protocol_name, "tcp")
    
    def test_can_handle(self):
        """Test can_handle method."""
        self.assertTrue(self.handler.can_handle(self.tcp_syn_packet))
        self.assertFalse(self.handler.can_handle(self.non_tcp_packet))
        self.assertFalse(self.handler.can_handle(IP()))
    
    def test_parse(self):
        """Test parse method."""
        result = self.handler.parse(self.tcp_syn_packet)
        
        # Check basic TCP fields
        self.assertEqual(result.name, "tcp")
        self.assertEqual(result.headers["sport"], 12345)
        self.assertEqual(result.headers["dport"], 80)
        self.assertEqual(result.headers["seq"], 1000)
        self.assertEqual(result.headers["ack"], 0)
        self.assertEqual(result.headers["flags"], 2)  # SYN flag = 2
        
        # Check metadata
        self.assertIn("length", result.metadata)
        self.assertIn("timestamp", result.metadata)
    
    def test_deep_inspect(self):
        """Test deep_inspect method."""
        info = self.handler.parse(self.tcp_psh_packet)
        self.handler.deep_inspect(self.tcp_psh_packet, info)
        
        # Check DPI results
        self.assertIn("flags_detailed", info.dpi_results)
        self.assertIn("window", info.dpi_results)
        self.assertIn("connections_states", info.dpi_results)
        
        # Check flags detailed
        self.assertTrue(info.dpi_results["flags_detailed"]["psh"])
        self.assertTrue(info.dpi_results["flags_detailed"]["ack"])
        self.assertFalse(info.dpi_results["flags_detailed"]["syn"])
        
        # Check window
        self.assertEqual(info.dpi_results["window"], 8192)
        
        # Test connection state inference
        info_syn = self.handler.parse(self.tcp_syn_packet)
        self.handler.deep_inspect(self.tcp_syn_packet, info_syn)
        self.assertEqual(info_syn.dpi_results["connections_states"], "connection_setup")
        
        info_synack = self.handler.parse(self.tcp_synack_packet)
        self.handler.deep_inspect(self.tcp_synack_packet, info_synack)
        self.assertEqual(info_synack.dpi_results["connections_states"], "connection_setup_reply")
        
        info_rst = self.handler.parse(self.tcp_rst_packet)
        self.handler.deep_inspect(self.tcp_rst_packet, info_rst)
        self.assertEqual(info_rst.dpi_results["connections_states"], "connection_reset")
    
    def test_tcp_options(self):
        """Test TCP options parsing."""
        info = self.handler.parse(self.tcp_options_packet)
        self.handler.deep_inspect(self.tcp_options_packet, info)
        
        # Check options
        self.assertIn("options", info.dpi_results)
        options = info.dpi_results["options"]
        
        # Should have 3 options
        self.assertEqual(len(options), 3)
        
        # Check MSS option
        mss_option = next((opt for opt in options if opt["kind"] == 2), None)  # MSS kind = 2
        self.assertIsNotNone(mss_option)
        
        # Check Timestamp option
        ts_option = next((opt for opt in options if opt["kind"] == 8), None)  # Timestamp kind = 8
        self.assertIsNotNone(ts_option)
    
    def test_error_handling(self):
        """Test error handling for invalid packets."""
        # Create an invalid packet (no TCP layer)
        invalid_packet = IP()
        
        # Should raise a specific exception
        with self.assertRaises(Exception):
            self.handler.parse(invalid_packet)


class TestUDPHandler(unittest.TestCase):
    """Tests for UDPHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.handler = UDPHandler()
        
        # Create sample packets
        self.udp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / UDP(sport=12345, dport=53, len=20)
        self.udp_packet_data = IP() / UDP(sport=12345, dport=53) / b"Test UDP data"
        self.non_udp_packet = IP() / TCP()
    
    def test_protocol_name(self):
        """Test protocol name."""
        self.assertEqual(self.handler.protocol_name, "udp")
    
    def test_can_handle(self):
        """Test can_handle method."""
        self.assertTrue(self.handler.can_handle(self.udp_packet))
        self.assertFalse(self.handler.can_handle(self.non_udp_packet))
        self.assertFalse(self.handler.can_handle(IP()))
    
    def test_parse(self):
        """Test parse method."""
        result = self.handler.parse(self.udp_packet)
        
        # Check basic UDP fields
        self.assertEqual(result.name, "udp")
        self.assertEqual(result.headers["sport"], 12345)
        self.assertEqual(result.headers["dport"], 53)
        self.assertEqual(result.headers["len"], 20)
        
        # Check metadata
        self.assertIn("length", result.metadata)
        self.assertIn("timestamp", result.metadata)
    
    def test_parse_with_data(self):
        """Test parsing UDP packet with data."""
        result = self.handler.parse(self.udp_packet_data)
        
        # Check payload
        self.assertEqual(result.data, b"Test UDP data")
    
    def test_error_handling(self):
        """Test error handling for invalid packets."""
        # Create an invalid packet (no UDP layer)
        invalid_packet = IP()
        
        # Should raise a specific exception
        with self.assertRaises(Exception):
            self.handler.parse(invalid_packet)


class TestICMPHandler(unittest.TestCase):
    """Tests for ICMPHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.handler = ICMPHandler()
        
        # Create sample packets
        self.icmp_echo_packet = IP() / ICMP(type=8, code=0, id=12345, seq=1)  # Echo request
        self.icmp_echo_reply_packet = IP() / ICMP(type=0, code=0, id=12345, seq=1)  # Echo reply
        self.icmp_dest_unreach_packet = IP() / ICMP(type=3, code=1)  # Destination host unreachable
        self.non_icmp_packet = IP() / TCP()
    
    def test_protocol_name(self):
        """Test protocol name."""
        self.assertEqual(self.handler.protocol_name, "icmp")
    
    def test_can_handle(self):
        """Test can_handle method."""
        self.assertTrue(self.handler.can_handle(self.icmp_echo_packet))
        self.assertFalse(self.handler.can_handle(self.non_icmp_packet))
        self.assertFalse(self.handler.can_handle(IP()))
    
    def test_parse_echo(self):
        """Test parse method for echo request."""
        result = self.handler.parse(self.icmp_echo_packet)
        
        # Check ICMP fields
        self.assertEqual(result.name, "icmp")
        self.assertEqual(result.headers["type"], 8)  # Echo request
        self.assertEqual(result.headers["code"], 0)
        self.assertEqual(result.headers["id"], 12345)
        self.assertEqual(result.headers["seq"], 1)
        
        # Check metadata
        self.assertIn("length", result.metadata)
        self.assertIn("timestamp", result.metadata)
    
    def test_parse_dest_unreach(self):
        """Test parse method for destination unreachable."""
        result = self.handler.parse(self.icmp_dest_unreach_packet)
        
        # Check ICMP fields
        self.assertEqual(result.name, "icmp")
        self.assertEqual(result.headers["type"], 3)  # Destination unreachable
        self.assertEqual(result.headers["code"], 1)  # Host unreachable
    
    def test_error_handling(self):
        """Test error handling for invalid packets."""
        # Create an invalid packet (no ICMP layer)
        invalid_packet = IP()
        
        # Should raise a specific exception
        with self.assertRaises(Exception):
            self.handler.parse(invalid_packet)


class TestHTTPHandler(unittest.TestCase):
    """Tests for HTTPHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.handler = HTTPHandler()
        
        # Create sample HTTP request packet
        http_request = (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Accept: text/html\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
        )
        self.http_request_packet = IP() / TCP(sport=12345, dport=80) / http_request
        
        # Create sample HTTP response packet
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Content-Length: 138\r\n"
            b"Set-Cookie: session=abc123; path=/; HttpOnly; Secure\r\n"
            b"\r\n"
            b"<!DOCTYPE html><html><body><h1>Example Page</h1><p>This is an example response.</p></body></html>"
        )
        self.http_response_packet = IP() / TCP(sport=80, dport=12345) / http_response
        
        # Create sample HTTP with JSON content
        http_json_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 43\r\n"
            b"\r\n"
            b'{"status":"success","message":"Data processed"}'
        )
        self.http_json_packet = IP() / TCP(sport=80, dport=12345) / http_json_response
        
        # Create malformed HTTP packet
        malformed_http = (
            b"GET /index.html\r\n"  # Missing HTTP version
            b"Host: example.com\r\n"
            b"\r\n"
        )
        self.malformed_http_packet = IP() / TCP(sport=12345, dport=80) / malformed_http
        
        self.non_http_packet = IP() / TCP() / b"Random data that is not HTTP"
    
    def test_protocol_name(self):
        """Test protocol name."""
        self.assertEqual(self.handler.protocol_name, "http")
    
    def test_can_handle(self):
        """Test can_handle method."""
        self.assertTrue(self.handler.can_handle(self.http_request_packet))
        self.assertTrue(self.handler.can_handle(self.http_response_packet))
        
        # Non-HTTP packets on port 80 might still be detected as HTTP
        # based on port, but content inspection should distinguish them
        non_http_on_80 = IP() / TCP(dport=80) / b"Random data"
        self.assertTrue(self.handler.can_handle(non_http_on_80))
        
        # Completely non-HTTP packet
        self.assertFalse(self.handler.can_handle(IP() / UDP()))
    
    def test_parse_request(self):
        """Test parsing HTTP request."""
        result = self.handler.parse(self.http_request_packet)
        
        # Check HTTP fields
        self.assertEqual(result.name, "http")
        self.assertEqual(result.version, "HTTP/1.1")
        self.assertTrue(result.metadata["is_request"])
        self.assertEqual(result.headers["method"], "GET")
        self.assertEqual(result.headers["path"], "/index.html")
        self.assertEqual(result.headers["Host"], "example.com")
        self.assertEqual(result.headers["User-Agent"], "Mozilla/5.0")
        self.assertEqual(result.headers["Accept"], "text/html")
        
        # Check metadata
        self.assertIn("timestamp", result.metadata)
    
    def test_parse_response(self):
        """Test parsing HTTP response."""
        result = self.handler.parse(self.http_response_packet)
        
        # Check HTTP fields
        self.assertEqual(result.name, "http")
        self.assertEqual(result.version, "HTTP/1.1")
        self.assertFalse(result.metadata.get("is_request", True))
        self.assertEqual(result.headers["status_code"], 200)
        self.assertEqual(result.headers["status_text"], "OK")
        self.assertEqual(result.headers["Server"], "Apache")
        self.assertEqual(result.headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(result.headers["Content-Length"], "138")
        
        # Check body
        self.assertIn(b"<h1>Example Page</h1>", result.data)
    
    def test_deep_inspect_response(self):
        """Test deep inspection of HTTP response."""
        info = self.handler.parse(self.http_response_packet)
        self.handler.deep_inspect(self.http_response_packet, info)
        
        # Check DPI results
        self.assertIn("content_analysis", info.dpi_results)
        self.assertEqual(info.dpi_results["content_analysis"]["type"], "html")
        
        # Check cookie security analysis
        self.assertIn("security", info.dpi_results)
        self.assertTrue(info.dpi_results["security"]["secure_cookie"])
        self.assertTrue(info.dpi_results["security"]["httponly_cookie"])
    
    def test_deep_inspect_json(self):
        """Test deep inspection of HTTP JSON response."""
        info = self.handler.parse(self.http_json_packet)
        self.handler.deep_inspect(self.http_json_packet, info)
        
        # Check DPI results
        self.assertIn("content_analysis", info.dpi_results)
        self.assertEqual(info.dpi_results["content_analysis"]["type"], "json")
        
        # Should have extracted JSON keys
        self.assertIn("json_keys", info.dpi_results["content_analysis"])
        json_keys = info.dpi_results["content_analysis"]["json_keys"]
        self.assertIn("status", json_keys)
        self.assertIn("message", json_keys)
    
    def test_malformed_http(self):
        """Test parsing malformed HTTP."""
        # Should still parse without error, but may have incomplete data
        try:
            result = self.handler.parse(self.malformed_http_packet)
            
            # Basic fields should still be there
            self.assertEqual(result.name, "http")
            self.assertTrue(result.metadata["is_request"])
            
            # May not recognize HTTP version
            self.assertIsNone(result.version)
            
        except Exception as e:
            self.fail(f"Parser failed on malformed HTTP with exception: {e}")


class TestDNSHandler(unittest.TestCase):
    """Tests for DNSHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.handler = DNSHandler()
        
        # Create DNS query packet
        self.dns_query = IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(
            rd=1,  # Recursion Desired
            qd=DNSQR(qname="example.com", qtype="A")
        )
        
        # Create DNS response packet
        self.dns_response = IP(src="8.8.8.8", dst="192.168.1.1") / UDP(sport=53, dport=12345) / DNS(
            qr=1,  # Response
            rd=1,  # Recursion Desired
            ra=1,  # Recursion Available
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", ttl=3600, type="A", rdata="93.184.216.34")
        )
        
        # Create DNS packet with multiple records (query and multiple answers)
        self.dns_multi = IP() / UDP(sport=53, dport=12345) / DNS(
            qr=1,  # Response
            qd=DNSQR(qname="example.com", qtype="MX"),
            an=[
                DNSRR(rrname="example.com", ttl=3600, type="MX", rdata="10 mail1.example.com."),
                DNSRR(rrname="example.com", ttl=3600, type="MX", rdata="20 mail2.example.com.")
            ]
        )
        
        # Create DNS packet with very long domain name (potential tunneling)
        long_domain = ".".join(["a" * 20] * 5) + ".example.com"  # Very long subdomain
        self.dns_tunnel = IP() / UDP(sport=12345, dport=53) / DNS(
            qd=DNSQR(qname=long_domain)
        )
        
        self.non_dns_packet = IP() / UDP(sport=12345, dport=80) / b"Random data"
    
    def test_protocol_name(self):
        """Test protocol name."""
        self.assertEqual(self.handler.protocol_name, "dns")
    
    def test_can_handle(self):
        """Test can_handle method."""
        self.assertTrue(self.handler.can_handle(self.dns_query))
        self.assertTrue(self.handler.can_handle(self.dns_response))
        self.assertFalse(self.handler.can_handle(self.non_dns_packet))
    
    def test_parse_query(self):
        """Test parsing DNS query."""
        result = self.handler.parse(self.dns_query)
        
        # Check DNS fields
        self.assertEqual(result.name, "dns")
        self.assertEqual(result.headers["qr"], 0)  # Query
        self.assertEqual(result.headers["rd"], 1)  # Recursion Desired
        
        # Check query section
        self.assertEqual(len(result.headers["queries"]), 1)
        query = result.headers["queries"][0]
        self.assertEqual(query["name"], "example.com.")
        self.assertEqual(query["type"], 1)  # A record
        
        # Check metadata
        self.assertIn("length", result.metadata)
        self.assertIn("timestamp", result.metadata)
    
    def test_parse_response(self):
        """Test parsing DNS response."""
        result = self.handler.parse(self.dns_response)
        
        # Check DNS fields
        self.assertEqual(result.name, "dns")
        self.assertEqual(result.headers["qr"], 1)  # Response
        self.assertEqual(result.headers["rd"], 1)  # Recursion Desired
        self.assertEqual(result.headers["ra"], 1)  # Recursion Available
        
        # Check query section
        self.assertEqual(len(result.headers["queries"]), 1)
        query = result.headers["queries"][0]
        self.assertEqual(query["name"], "example.com.")
        
        # Check answer section
        self.assertEqual(len(result.headers["answers"]), 1)
        answer = result.headers["answers"][0]
        self.assertEqual(answer["name"], "example.com.")
        self.assertEqual(answer["data"], "93.184.216.34")
    
    def test_parse_multi(self):
        """Test parsing DNS with multiple records."""
        result = self.handler.parse(self.dns_multi)
        
        # Check answer section with multiple records
        self.assertEqual(len(result.headers["answers"]), 2)
        self.assertEqual(result.headers["answers"][0]["type"], 15)  # MX record
        self.assertEqual(result.headers["answers"][1]["type"], 15)  # MX record
    
    def test_deep_inspect_tunneling(self):
        """Test deep inspection for DNS tunneling detection."""
        result = self.handler.parse(self.dns_tunnel)
        self.handler.deep_inspect(self.dns_tunnel, result)
        
        # Should detect suspicious long domain
        self.assertIn("suspicious", result.dpi_results)
        self.assertTrue(result.dpi_results["suspicious"])
        self.assertIn("reason", result.dpi_results)
        self.assertIn("tunneling", result.dpi_results["reason"].lower())
    
    def test_error_handling(self):
        """Test error handling for invalid packets."""
        # Create an invalid packet (no DNS layer)
        invalid_packet = IP() / UDP()
        
        # Should raise a specific exception
        with self.assertRaises(Exception):
            self.handler.parse(invalid_packet)


class TestSMTPHandler(unittest.TestCase):
    """Tests for SMTPHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.handler = SMTPHandler()
        
        # Create SMTP command packets
        self.smtp_ehlo = IP() / TCP(sport=12345, dport=25) / b"EHLO client.example.com\r\n"
        self.smtp_mail_from = IP() / TCP(sport=12345, dport=25) / b"MAIL FROM:<sender@example.com>\r\n"
        self.smtp_rcpt_to = IP() / TCP(sport=12345, dport=25) / b"RCPT TO:<recipient@example.org>\r\n"
        self.smtp_data = IP() / TCP(sport=12345, dport=25) / b"DATA\r\n"
        self.smtp_quit = IP() / TCP(sport=12345, dport=25) / b"QUIT\r\n"
        # Create SMTP response packets
        self.smtp_greeting = IP() / TCP(sport=25, dport=12345) / b"220 mail.example.com ESMTP Server Ready\r\n"
        self.smtp_ehlo_response = IP() / TCP(sport=25, dport=12345) / b"250-mail.example.com\r\n250-SIZE 52428800\r\n250-AUTH LOGIN PLAIN\r\n250 HELP\r\n"
        self.smtp_mail_from_response = IP() / TCP(sport=25, dport=12345) / b"250 OK\r\n"
        self.smtp_rcpt_to_response = IP() / TCP(sport=25, dport=12345) / b"250 Accepted\r\n"
        self.smtp_data_response = IP() / TCP(sport=25, dport=12345) / b"354 Start mail input; end with <CRLF>.<CRLF>\r\n"
        self.smtp_quit_response = IP() / TCP(sport=25, dport=12345) / b"221 mail.example.com Service closing transmission channel\r\n"
        self.smtp_error_response = IP() / TCP(sport=25, dport=12345) / b"550 Requested action not taken: mailbox unavailable\r\n"
        
        # Create SMTP data packet with email content
        email_content = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.org\r\n"
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
        self.smtp_email_packet = IP() / TCP(sport=12345, dport=25) / email_content
        
        self.non_smtp_packet = IP() / TCP(sport=12345, dport=80) / b"Random data"
    
    def test_protocol_name(self):
        """Test protocol name."""
        self.assertEqual(self.handler.protocol_name, "smtp")
    
    def test_protocol_aliases(self):
        """Test protocol aliases."""
        aliases = self.handler.protocol_aliases
        self.assertIn("email", aliases)
        self.assertIn("mail", aliases)
    
    def test_can_handle(self):
        """Test can_handle method."""
        self.assertTrue(self.handler.can_handle(self.smtp_ehlo))
        self.assertTrue(self.handler.can_handle(self.smtp_greeting))
        self.assertFalse(self.handler.can_handle(self.non_smtp_packet))
        self.assertFalse(self.handler.can_handle(IP() / UDP()))
    
    def test_parse_commands(self):
        """Test parsing SMTP commands."""
        # Test EHLO command
        result = self.handler.parse(self.smtp_ehlo)
        self.assertEqual(result.name, "smtp")
        self.assertTrue(result.metadata["is_command"])
        self.assertEqual(result.headers["command"], "EHLO")
        self.assertEqual(result.headers["parameter"], "client.example.com")
        
        # Test MAIL FROM command
        result = self.handler.parse(self.smtp_mail_from)
        self.assertEqual(result.name, "smtp")
        self.assertTrue(result.metadata["is_command"])
        self.assertEqual(result.headers["command"], "MAIL FROM")
        self.assertEqual(result.headers["parameter"], "<sender@example.com>")
        
        # Test RCPT TO command
        result = self.handler.parse(self.smtp_rcpt_to)
        self.assertEqual(result.name, "smtp")
        self.assertTrue(result.metadata["is_command"])
        self.assertEqual(result.headers["command"], "RCPT TO")
        self.assertEqual(result.headers["parameter"], "<recipient@example.org>")
        
        # Test DATA command
        result = self.handler.parse(self.smtp_data)
        self.assertEqual(result.name, "smtp")
        self.assertTrue(result.metadata["is_command"])
        self.assertEqual(result.headers["command"], "DATA")
        
        # Test QUIT command
        result = self.handler.parse(self.smtp_quit)
        self.assertEqual(result.name, "smtp")
        self.assertTrue(result.metadata["is_command"])
        self.assertEqual(result.headers["command"], "QUIT")
    
    def test_parse_responses(self):
        """Test parsing SMTP responses."""
        # Test greeting response
        result = self.handler.parse(self.smtp_greeting)
        self.assertEqual(result.name, "smtp")
        self.assertTrue(result.metadata["is_response"])
        self.assertEqual(result.headers["response_code"], "220")
        self.assertEqual(result.headers["response_message"], "mail.example.com ESMTP Server Ready")
        
        # Test EHLO response
        result = self.handler.parse(self.smtp_ehlo_response)
        self.assertEqual(result.name, "smtp")
        self.assertTrue(result.metadata["is_response"])
        self.assertEqual(result.headers["response_code"], "250")
        
        # Test error response
        result = self.handler.parse(self.smtp_error_response)
        self.assertEqual(result.name, "smtp")
        self.assertTrue(result.metadata["is_response"])
        self.assertEqual(result.headers["response_code"], "550")
        self.assertEqual(result.headers["response_message"], "Requested action not taken: mailbox unavailable")
    
    def test_parse_email_data(self):
        """Test parsing SMTP email data."""
        result = self.handler.parse(self.smtp_email_packet)
        self.assertEqual(result.name, "smtp")
        
        # Check content
        self.assertIn(b"From: sender@example.com", result.data)
        self.assertIn(b"Content-Type: multipart/mixed", result.data)
        self.assertIn(b"boundary123", result.data)
        self.assertIn(b"Content-Disposition: attachment", result.data)
    
    def test_deep_inspect_email(self):
        """Test deep inspection of SMTP email."""
        info = self.handler.parse(self.smtp_email_packet)
        self.handler.deep_inspect(self.smtp_email_packet, info)
        
        # Check DPI results
        self.assertIn("email_addresses", info.dpi_results)
        self.assertIn("sender@example.com", info.dpi_results["email_addresses"])
        self.assertIn("recipient@example.org", info.dpi_results["email_addresses"])
        
        # Check attachment detection
        self.assertIn("has_attachment", info.dpi_results)
        self.assertTrue(info.dpi_results["has_attachment"])
        
        # Check multipart detection
        self.assertIn("is_multipart", info.dpi_results)
        self.assertTrue(info.dpi_results["is_multipart"])
        
        # Check boundary detection
        self.assertIn("boundary", info.dpi_results)
        self.assertEqual(info.dpi_results["boundary"], "boundary123")
    
    def test_deep_inspect_mail_from(self):
        """Test deep inspection of MAIL FROM command."""
        info = self.handler.parse(self.smtp_mail_from)
        self.handler.deep_inspect(self.smtp_mail_from, info)
        
        # Should extract email address
        self.assertIn("email_addresses", info.dpi_results)
        self.assertIn("sender@example.com", info.dpi_results["email_addresses"])
    
    def test_error_handling(self):
        """Test error handling for invalid packets."""
        # Create an invalid packet (no TCP layer)
        invalid_packet = IP()
        
        # Should raise a specific exception
        with self.assertRaises(Exception):
            self.handler.parse(invalid_packet)


if __name__ == "__main__":
    unittest.main()
