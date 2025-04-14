

import logging
import time
import re
from typing import Dict, List, Any, Optional, Tuple, Callable, Set, Pattern
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
from scapy.packet import Packet
logger = logging.getLogger(__name__)


@dataclass
class ProtocolInfo:
    name: str
    version: Optional[str] = None
    headers: Dict[str, Any] = field(default_factory=dict)
    data: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    fingerprint: Optional[str] = None
    confidence: float = 1.0  # Confidence level for protocol identification (0.0-1.0)
    dpi_results: Dict[str, Any] = field(default_factory=dict)  # Results from deep packet inspection


class ProtocolFingerprint:
    
    def __init__(self):
        self.fingerprints: Dict[str, List[Dict[str, Any]]] = {
            "http": [
                {"pattern": rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE) .+ HTTP/\d\.\d", "confidence": 0.9},
                {"pattern": rb"HTTP/\d\.\d \d{3}", "confidence": 0.8},
            ],
            "dns": [
                {"pattern": rb"\x00\x01\x00\x00|\x00\x01\x00\x01", "confidence": 0.7},
            ],
            "smtp": [
                {"pattern": rb"^(HELO|EHLO|MAIL FROM|RCPT TO|DATA|QUIT)", "confidence": 0.9},
                {"pattern": rb"^220 .* SMTP", "confidence": 0.9},
                {"pattern": rb"^250 .*", "confidence": 0.7},
            ],
            "ftp": [
                {"pattern": rb"^(USER|PASS|LIST|RETR|STOR|QUIT|PWD|CWD)", "confidence": 0.9},
                {"pattern": rb"^220 .* FTP", "confidence": 0.9},
            ],
            "ssh": [
                {"pattern": rb"^SSH-\d\.\d", "confidence": 0.9},
            ],
        }
        
        for proto, signatures in self.fingerprints.items():
            for signature in signatures:
                signature["compiled"] = re.compile(signature["pattern"], re.IGNORECASE | re.MULTILINE)
    
    def identify_protocol(self, data: bytes) -> List[Tuple[str, float]]:
        if not data:
            return []
            
        results = []
        for proto, signatures in self.fingerprints.items():
            for signature in signatures:
                if signature["compiled"].search(data):
                    results.append((proto, signature["confidence"]))
                    break
        
        return sorted(results, key=lambda x: x[1], reverse=True)


class ProtocolHandler(ABC):
    
    @property
    @abstractmethod
    def protocol_name(self) -> str:
        pass
    
    @property
    def protocol_aliases(self) -> List[str]:
        return []
    
    @abstractmethod
    def can_handle(self, packet: scapy.Packet) -> bool:
        pass
    
    @abstractmethod
    def parse(self, packet: scapy.Packet) -> ProtocolInfo:
        pass
    
    def deep_inspect(self, packet: scapy.Packet, info: ProtocolInfo) -> None:
        pass


class IPHandler(ProtocolHandler):
    
    @property
    def protocol_name(self) -> str:
        return "ip"
    
    def can_handle(self, packet: scapy.Packet) -> bool:
        return IP in packet
    
    def parse(self, packet: scapy.Packet) -> ProtocolInfo:
        ip_layer = packet[IP]
        info = ProtocolInfo(
            name="ip",
            version=f"IPv{ip_layer.version}",
            headers={
                "src": ip_layer.src,
                "dst": ip_layer.dst,
                "ttl": ip_layer.ttl,
                "id": ip_layer.id,
                "proto": ip_layer.proto,
            },
            metadata={
                "length": len(ip_layer),
                "timestamp": time.time(),
            }
        )
        return info
    
    def deep_inspect(self, packet: scapy.Packet, info: ProtocolInfo) -> None:
        ip_layer = packet[IP]
        info.dpi_results.update({
            "flags": ip_layer.flags,
            "frag": ip_layer.frag,
            "tos": ip_layer.tos,
            "options": ip_layer.options if hasattr(ip_layer, 'options') else [],
        })


class TCPHandler(ProtocolHandler):
    
    @property
    def protocol_name(self) -> str:
        return "tcp"
    
    def can_handle(self, packet: scapy.Packet) -> bool:
        return TCP in packet
    
    def parse(self, packet: scapy.Packet) -> ProtocolInfo:
        tcp_layer = packet[TCP]
        info = ProtocolInfo(
            name="tcp",
            headers={
                "sport": tcp_layer.sport,
                "dport": tcp_layer.dport,
                "seq": tcp_layer.seq,
                "ack": tcp_layer.ack,
                "flags": tcp_layer.flags,
            },
            data=bytes(tcp_layer.payload) if tcp_layer.payload else None,
            metadata={
                "length": len(tcp_layer),
                "timestamp": time.time(),
            }
        )
        return info
    
    def deep_inspect(self, packet: scapy.Packet, info: ProtocolInfo) -> None:
        tcp_layer = packet[TCP]
        info.dpi_results.update({
            "window": tcp_layer.window,
            "options": [{'kind': opt[0], 'value': opt[1:]} for opt in tcp_layer.options],
            "flags_detailed": {
                "syn": bool(tcp_layer.flags & 0x02),
                "ack": bool(tcp_layer.flags & 0x10),
                "fin": bool(tcp_layer.flags & 0x01),
                "rst": bool(tcp_layer.flags & 0x04),
                "psh": bool(tcp_layer.flags & 0x08),
                "urg": bool(tcp_layer.flags & 0x20),
                "ece": bool(tcp_layer.flags & 0x40),
                "cwr": bool(tcp_layer.flags & 0x80),
            },
            "connections_states": self._infer_tcp_state(tcp_layer),
        })
    
    def _infer_tcp_state(self, tcp_layer) -> str:
        flags = tcp_layer.flags
        if flags & 0x02 and not flags & 0x10:  # SYN, !ACK
            return "connection_setup"
        elif flags & 0x02 and flags & 0x10:    # SYN, ACK
            return "connection_setup_reply"
        elif flags & 0x01:                     # FIN
            return "connection_teardown"
        elif flags & 0x04:                     # RST
            return "connection_reset"
        elif flags & 0x08 and flags & 0x10:    # PSH, ACK
            return "data_transfer"
        elif flags & 0x10:                     # ACK
            return "established"
        return "unknown"


class UDPHandler(ProtocolHandler):
    
    @property
    def protocol_name(self) -> str:
        return "udp"
    
    def can_handle(self, packet: scapy.Packet) -> bool:
        return UDP in packet
    
    def parse(self, packet: scapy.Packet) -> ProtocolInfo:
        udp_layer = packet[UDP]
        info = ProtocolInfo(
            name="udp",
            headers={
                "sport": udp_layer.sport,
                "dport": udp_layer.dport,
                "len": udp_layer.len,
            },
            data=bytes(udp_layer.payload) if udp_layer.payload else None,
            metadata={
                "length": len(udp_layer),
                "timestamp": time.time(),
            }
        )
        return info


class ICMPHandler(ProtocolHandler):
    
    @property
    def protocol_name(self) -> str:
        return "icmp"
    
    def can_handle(self, packet: scapy.Packet) -> bool:
        return ICMP in packet
    
    def parse(self, packet: scapy.Packet) -> ProtocolInfo:
        icmp_layer = packet[ICMP]
        info = ProtocolInfo(
            name="icmp",
            headers={
                "type": icmp_layer.type,
                "code": icmp_layer.code,
                "id": icmp_layer.id if hasattr(icmp_layer, 'id') else None,
                "seq": icmp_layer.seq if hasattr(icmp_layer, 'seq') else None,
            },
            data=bytes(icmp_layer.payload) if icmp_layer.payload else None,
            metadata={
                "length": len(icmp_layer),
                "timestamp": time.time(),
            }
        )
        return info


class HTTPHandler(ProtocolHandler):
    
    @property
    def protocol_name(self) -> str:
        return "http"
    
    def can_handle(self, packet: scapy.Packet) -> bool:
        if not TCP in packet:
            return False
            
        tcp_layer = packet[TCP]
        if tcp_layer.dport in (80, 8080, 8000) or tcp_layer.sport in (80, 8080, 8000):
            if tcp_layer.payload:
                payload = bytes(tcp_layer.payload)
                return (b"GET " in payload[:10] or 
                        b"POST " in payload[:10] or
                        b"HTTP/" in payload[:10] or
                        b"HTTP/" in payload)
            return True
        return False
    
    def parse(self, packet: scapy.Packet) -> ProtocolInfo:
        payload = bytes(packet[TCP].payload) if TCP in packet and packet[TCP].payload else b""
        
        is_request = any(method in payload[:10] for method in 
                        [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"TRACE "])
        
        headers = {}
        version = None
        
        if is_request:
            try:
                request_line, headers_data = payload.split(b"\r\n", 1)
                method, path, http_version = request_line.decode('utf-8', 'ignore').split(" ")
                headers["method"] = method
                headers["path"] = path
                version = http_version
                
                header_lines = headers_data.split(b"\r\n\r\n")[0].split(b"\r\n")
                for line in header_lines:
                    if b":" in line:
                        key, value = line.split(b":", 1)
                        headers[key.decode('utf-8', 'ignore').strip()] = value.decode('utf-8', 'ignore').strip()
            except Exception as e:
                logger.warning(f"Error parsing HTTP request: {e}")
        else:
            try:
                status_line, headers_data = payload.split(b"\r\n", 1)
                http_version, status_code, *status_text = status_line.decode('utf-8', 'ignore').split(" ")
                headers["status_code"] = int(status_code)
                headers["status_text"] = " ".join(status_text)
                version = http_version
                
                header_lines = headers_data.split(b"\r\n\r\n")[0].split(b"\r\n")
                for line in header_lines:
                    if b":" in line:
                        key, value = line.split(b":", 1)
                        headers[key.decode('utf-8', 'ignore').strip()] = value.decode('utf-8', 'ignore').strip()
            except Exception as e:
                logger.warning(f"Error parsing HTTP response: {e}")
                
        body = None
        if b"\r\n\r\n" in payload:
            try:
                body = payload.split(b"\r\n\r\n", 1)[1]
            except Exception as e:
                logger.warning(f"Error extracting HTTP body: {e}")
        
        info = ProtocolInfo(
            name="http",
            version=version,
            headers=headers,
            data=body,
            metadata={
                "is_request": is_request,
                "timestamp": time.time(),
            }
        )
        return info
    
    def deep_inspect(self, packet: scapy.Packet, info: ProtocolInfo) -> None:
        """Perform deep inspection of HTTP packet."""
        if not info.data:
            return
            
        content_type = info.headers.get("Content-Type", "").lower()
        
        info.dpi_results["content_analysis"] = {}
        
        if "json" in content_type:
            try:
                import json
                json_data = json.loads(info.data)
                info.dpi_results["content_analysis"]["json_keys"] = list(json_data.keys()) if isinstance(json_data, dict) else []
                info.dpi_results["content_analysis"]["type"] = "json"
            except:
                pass
                
        elif "xml" in content_type or info.data.startswith(b"<?xml"):
            info.dpi_results["content_analysis"]["type"] = "xml"
            
        elif "html" in content_type or info.data.startswith(b"<!DOCTYPE html") or info.data.startswith(b"<html"):
            info.dpi_results["content_analysis"]["type"] = "html"
            
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(info.data, 'html.parser')
                meta_tags = {}
                for tag in soup.find_all('meta'):
                    if tag.get('name'):
                        meta_tags[tag.get('name')] = tag.get('content')
                info.dpi_results["content_analysis"]["meta_tags"] = meta_tags
            except ImportError:
                logger.warning("BeautifulSoup not available for HTML deep inspection")
                
        if "set-cookie" in info.headers:
            cookie = info.headers["set-cookie"]
            info.dpi_results["security"] = {}
            info.dpi_results["security"]["secure_cookie"] = "secure" in cookie.lower()
            info.dpi_results["security"]["httponly_cookie"] = "httponly" in cookie.lower()
            
        if info.data:
            url_pattern = re.compile(rb'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
            urls = url_pattern.findall(info.data)
            if urls:
                info.dpi_results["extracted_urls"] = [url.decode('utf-8', 'ignore') for url in urls]


class DNSHandler(ProtocolHandler):
    
    @property
    def protocol_name(self) -> str:
        return "dns"
    
    def can_handle(self, packet: scapy.Packet) -> bool:
        return DNS in packet
    
    def parse(self, packet: scapy.Packet) -> ProtocolInfo:
        dns_layer = packet[DNS]
        
        queries = []
        answers = []
        
        if dns_layer.qd:
            for i in range(dns_layer.qdcount):
                try:
                    qname = dns_layer.qd[i].qname.decode('utf-8', 'ignore')
                    qtype = dns_layer.qd[i].qtype
                    queries.append({"name": qname, "type": qtype})
                except Exception as e:
                    logger.warning(f"Error parsing DNS query: {e}")
        
        if dns_layer.an:
            for i in range(dns_layer.ancount):
                try:
                    rname = dns_layer.an[i].rrname.decode('utf-8', 'ignore')
                    rdata = None
                    if hasattr(dns_layer.an[i], 'rdata'):
                        if isinstance(dns_layer.an[i].rdata, bytes):
                            rdata = dns_layer.an[i].rdata.decode('utf-8', 'ignore')
                        else:
                            rdata = str(dns_layer.an[i].rdata)
                    answers.append({"name": rname, "data": rdata, "type": dns_layer.an[i].type})
                except Exception as e:
                    logger.warning(f"Error parsing DNS answer: {e}")
        
        info = ProtocolInfo(
            name="dns",
            headers={
                "id": dns_layer.id,
                "opcode": dns_layer.opcode,
                "rcode": dns_layer.rcode,
                "qr": dns_layer.qr,  # 0 for query, 1 for response
                "aa": dns_layer.aa,  # Authoritative Answer
                "tc": dns_layer.tc,  # Truncated
                "rd": dns_layer.rd,  # Recursion Desired
                "ra": dns_layer.ra,  # Recursion Available
                "queries": queries,
                "answers": answers
            },
            metadata={
                "length": len(dns_layer),
                "timestamp": time.time(),
            }
        )
        return info
    
    def deep_inspect(self, packet: scapy.Packet, info: ProtocolInfo) -> None:
        dns_layer = packet[DNS]
        
        if dns_layer.ns:
            authority = []
            for i in range(dns_layer.nscount):
                try:
                    authority.append({
                        "name": dns_layer.ns[i].rrname.decode('utf-8', 'ignore'),
                        "type": dns_layer.ns[i].type
                    })
                except Exception as e:
                    logger.warning(f"Error parsing DNS authority: {e}")
            info.dpi_results["authority"] = authority
            
        if dns_layer.ar:
            additional = []
            for i in range(dns_layer.arcount):
                try:
                    additional.append({
                        "name": dns_layer.ar[i].rrname.decode('utf-8', 'ignore'),
                        "type": dns_layer.ar[i].type
                    })
                except Exception as e:
                    logger.warning(f"Error parsing DNS additional: {e}")
            info.dpi_results["additional"] = additional
            
        if info.headers["queries"] and len(info.headers["queries"]) > 0:
            query = info.headers["queries"][0]["name"]
            if len(query) > 50:  
                info.dpi_results["suspicious"] = True
                info.dpi_results["reason"] = "Unusually long domain name, possible DNS tunneling"


class SMTPHandler(ProtocolHandler):
    
    @property
    def protocol_name(self) -> str:
        return "smtp"
    
    @property
    def protocol_aliases(self) -> List[str]:
        return ["email", "mail"]
    
    def can_handle(self, packet: scapy.Packet) -> bool:
        if not TCP in packet:
            return False
            
        tcp_layer = packet[TCP]
        if tcp_layer.dport in (25, 465, 587) or tcp_layer.sport in (25, 465, 587):
            if tcp_layer.payload:
                payload = bytes(tcp_layer.payload)
                smtp_patterns = [
                    b"HELO ", b"EHLO ", b"MAIL FROM:", b"RCPT TO:", b"DATA", b"QUIT",
                    b"220 ", b"250 ", b"354 ", b"221 ", b"STARTTLS"
                ]
                return any(pattern in payload for pattern in smtp_patterns)
            return True
        return False
    
    def parse(self, packet: scapy.Packet) -> ProtocolInfo:
        tcp_layer = packet[TCP]
        payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
        
        is_command = any(cmd in payload for cmd in [b"HELO ", b"EHLO ", b"MAIL FROM:", b"RCPT TO:", b"DATA", b"QUIT", b"STARTTLS"])
        is_response = payload.startswith((b"220 ", b"250 ", b"354 ", b"221 ", b"235 ", b"334 ", b"535 "))
        
        headers = {}
        
        if is_command:
            try:
                cmd_line = payload.split(b"\r\n")[0].decode('utf-8', 'ignore')
                if " " in cmd_line:
                    cmd, param = cmd_line.split(" ", 1)
                    headers["command"] = cmd
                    headers["parameter"] = param
                else:
                    headers["command"] = cmd_line
            except Exception as e:
                logger.warning(f"Error parsing SMTP command: {e}")
        
        elif is_response:
            try:
                resp_line = payload.split(b"\r\n")[0].decode('utf-8', 'ignore')
                code = resp_line[:3]
                message = resp_line[4:]
                headers["response_code"] = code
                headers["response_message"] = message
            except Exception as e:
                logger.warning(f"Error parsing SMTP response: {e}")
        
        info = ProtocolInfo(
            name="smtp",
            headers=headers,
            data=payload,
            metadata={
                "is_command": is_command,
                "is_response": is_response,
                "length": len(payload),
                "timestamp": time.time(),
            }
        )
        return info
    
    def deep_inspect(self, packet: scapy.Packet, info: ProtocolInfo) -> None:
        if not info.data:
            return
            
        data = info.data.decode('utf-8', 'ignore')
        
        email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+')
        emails = email_pattern.findall(data)
        if emails:
            info.dpi_results["email_addresses"] = emails
            
        if b"Content-Disposition: attachment" in info.data:
            info.dpi_results["has_attachment"] = True
            
        if info.metadata.get("is_command") and info.headers.get("command") == "DATA":
            if b"Content-Type: multipart" in info.data:
                info.dpi_results["is_multipart"] = True
                
                boundary_match = re.search(rb'boundary="([^"]+)"', info.data)
                if boundary_match:
                    info.dpi_results["boundary"] = boundary_match.group(1).decode('utf-8', 'ignore')


class ProtocolParser:
    
    def __init__(self):
        self.protocol_handlers = []
        self.fingerprinter = ProtocolFingerprint()
        
        self.register_handler(IPHandler())
        self.register_handler(TCPHandler())
        self.register_handler(UDPHandler())
        self.register_handler(ICMPHandler())
        self.register_handler(HTTPHandler())
        self.register_handler(DNSHandler())
        self.register_handler(SMTPHandler())
        
        self.supported_protocols = {
            "ip": self._parse_ip,
            "tcp": self._parse_tcp,
            "udp": self._parse_udp,
            "icmp": self._parse_icmp,
            "http": self._parse_http,
            "dns": self._parse_dns,
            "smtp": self._parse_smtp,
        }
    
    def register_handler(self, handler: ProtocolHandler) -> None:
        self.protocol_handlers.append(handler)
        self.supported_protocols[handler.protocol_name] = lambda pkt: handler.parse(pkt)
    
    def parse_packet(self, packet: scapy.Packet) -> Dict[str, ProtocolInfo]:
        results: Dict[str, ProtocolInfo] = {}
        
        for handler in self.protocol_handlers:
            if handler.can_handle(packet):
                try:
                    protocol_info = handler.parse(packet)
                    handler.deep_inspect(packet, protocol_info)
                    results[handler.protocol_name] = protocol_info
                except Exception as e:
                    logger.error(f"Error parsing {handler.protocol_name} protocol: {e}")
        
        self._fingerprint_payloads(packet, results)
        
        return results
    
    def _fingerprint_payloads(self, packet: scapy.Packet, results: Dict[str, ProtocolInfo]) -> None:
        payload_data = None
        
        if TCP in packet and packet[TCP].payload and "http" not in results and "smtp" not in results:
            payload_data = bytes(packet[TCP].payload)
        elif UDP in packet and packet[UDP].payload and "dns" not in results:
            payload_data = bytes(packet[UDP].payload)
            
        if payload_data:
            fingerprints = self.fingerprinter.identify_protocol(payload_data)
            if fingerprints:
                proto_name, confidence = fingerprints[0] 
                
                if proto_name not in results and confidence > 0.6:
                    info = ProtocolInfo(
                        name=proto_name,
                        data=payload_data,
                        confidence=confidence,
                        fingerprint=f"Detected via pattern matching",
                        metadata={
                            "fingerprinted": True,
                            "timestamp": time.time(),
                        }
                    )
                    results[proto_name] = info
    
    def _has_protocol(self, packet: scapy.Packet, proto_name: str) -> bool:
        for handler in self.protocol_handlers:
            if handler.protocol_name == proto_name or proto_name in handler.protocol_aliases:
                return handler.can_handle(packet)
                
        if proto_name == "ip":
            return IP in packet
        elif proto_name == "tcp":
            return TCP in packet
        elif proto_name == "udp":
            return UDP in packet
        elif proto_name == "icmp":
            return ICMP in packet
        elif proto_name == "http":
            if not TCP in packet:
                return False
            tcp_layer = packet[TCP]
            if tcp_layer.dport in (80, 8080, 8000) or tcp_layer.sport in (80, 8080, 8000):
                if tcp_layer.payload:
                    payload = bytes(tcp_layer.payload)
                    return (b"GET " in payload[:10] or 
                            b"POST " in payload[:10] or
                            b"HTTP/" in payload[:10])
        elif proto_name == "dns":
            return DNS in packet
        elif proto_name == "smtp":
            if not TCP in packet:
                return False
            tcp_layer = packet[TCP]
            if tcp_layer.dport in (25, 465, 587) or tcp_layer.sport in (25, 465, 587):
                if tcp_layer.payload:
                    payload = bytes(tcp_layer.payload)
                    smtp_patterns = [b"HELO ", b"EHLO ", b"MAIL FROM:", b"RCPT TO:", b"DATA", b"QUIT",
                                    b"220 ", b"250 ", b"354 ", b"221 "]
                    return any(pattern in payload for pattern in smtp_patterns)
        
        return False
    
    
    def _parse_ip(self, packet: scapy.Packet) -> ProtocolInfo:
        for handler in self.protocol_handlers:
            if handler.protocol_name == "ip" and handler.can_handle(packet):
                return handler.parse(packet)
        raise ValueError("No IP handler found or packet doesn't contain IP")
    
    def _parse_tcp(self, packet: scapy.Packet) -> ProtocolInfo:
        for handler in self.protocol_handlers:
            if handler.protocol_name == "tcp" and handler.can_handle(packet):
                return handler.parse(packet)
        raise ValueError("No TCP handler found or packet doesn't contain TCP")
    
    def _parse_udp(self, packet: scapy.Packet) -> ProtocolInfo:
        for handler in self.protocol_handlers:
            if handler.protocol_name == "udp" and handler.can_handle(packet):
                return handler.parse(packet)
        raise ValueError("No UDP handler found or packet doesn't contain UDP")
    
    def _parse_icmp(self, packet: scapy.Packet) -> ProtocolInfo:
        for handler in self.protocol_handlers:
            if handler.protocol_name == "icmp" and handler.can_handle(packet):
                return handler.parse(packet)
        raise ValueError("No ICMP handler found or packet doesn't contain ICMP")
    
    def _parse_http(self, packet: scapy.Packet) -> ProtocolInfo:
        for handler in self.protocol_handlers:
            if handler.protocol_name == "http" and handler.can_handle(packet):
                return handler.parse(packet)
        raise ValueError("No HTTP handler found or packet doesn't contain HTTP")
    
    def _parse_dns(self, packet: scapy.Packet) -> ProtocolInfo:
        for handler in self.protocol_handlers:
            if handler.protocol_name == "dns" and handler.can_handle(packet):
                return handler.parse(packet)
        raise ValueError("No DNS handler found or packet doesn't contain DNS")
    
    def _parse_smtp(self, packet: scapy.Packet) -> ProtocolInfo:
        for handler in self.protocol_handlers:
            if handler.protocol_name == "smtp" and handler.can_handle(packet):
                return handler.parse(packet)
        raise ValueError("No SMTP handler found or packet doesn't contain SMTP")
        
    def get_supported_protocols(self) -> List[str]:
        return [handler.protocol_name for handler in self.protocol_handlers]
        
    def fingerprint_packet(self, packet: scapy.Packet) -> List[Tuple[str, float]]:
        """как же я мучалсяс этим
        """
        results = []
        
        payload_data = None
        if TCP in packet and packet[TCP].payload:
            payload_data = bytes(packet[TCP].payload)
        elif UDP in packet and packet[UDP].payload:
            payload_data = bytes(packet[UDP].payload)
            
        if payload_data:
            fingerprint_results = self.fingerprinter.identify_protocol(payload_data)
            results.extend(fingerprint_results)
            
        return results
