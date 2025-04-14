#имплементари

import asyncio
import logging
import time
from typing import Dict, List, Optional, Callable, Any

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP

logger = logging.getLogger(__name__)


class CaptureEngine:
    
    def __init__(self, interface: Optional[str] = None, buffer_size: int = 1024):
        self.interface = interface
        self.buffer_size = buffer_size
        self.running = False
        self.packet_buffer: List[scapy.Packet] = []
        self.capture_filter = None
        self.packet_callbacks: List[Callable[[scapy.Packet], None]] = []
        self.stats: Dict[str, Any] = {
            "start_time": 0,
            "packet_count": 0,
            "bytes_captured": 0,
            "protocols": {
                "tcp": 0,
                "udp": 0,
                "icmp": 0,
                "other": 0
            }
        }
    
    def set_filter(self, filter_exp: str) -> None:
        self.capture_filter = filter_exp
        logger.info(f"Filter set to: {filter_exp}")
    
    def register_packet_callback(self, callback: Callable[[scapy.Packet], None]) -> None:
        self.packet_callbacks.append(callback)
    
    def _process_packet(self, packet: scapy.Packet) -> None:
        self.stats["packet_count"] += 1
        
        if hasattr(packet, "len"):
            self.stats["bytes_captured"] += packet.len
        
        if packet.haslayer(TCP):
            self.stats["protocols"]["tcp"] += 1
        elif packet.haslayer(UDP):
            self.stats["protocols"]["udp"] += 1
        elif packet.haslayer(ICMP):
            self.stats["protocols"]["icmp"] += 1
        else:
            self.stats["protocols"]["other"] += 1
        
        self.packet_buffer.append(packet)
        if len(self.packet_buffer) > self.buffer_size:
            self.packet_buffer.pop(0)
        
        for callback in self.packet_callbacks:
            try:
                callback(packet)
            except Exception as e:
                logger.error(f"Error in packet callback: {e}")
    
    async def start_capture(self, packet_count: int = 0) -> None:
        logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
        
        self.running = True
        self.stats["start_time"] = time.time()
        
        loop = asyncio.get_event_loop()
        
        def sniff_packets():
            try:
                scapy.sniff(
                    iface=self.interface,
                    filter=self.capture_filter,
                    prn=self._process_packet,
                    store=False,
                    count=packet_count or None,
                    stop_filter=lambda _: not self.running
                )
            except Exception as e:
                logger.error(f"Error in packet sniffing: {e}")
                self.running = False
        
        await loop.run_in_executor(None, sniff_packets)
    
    async def stop_capture(self) -> None:
        logger.info("Stopping packet capture")
        self.running = False
        
        duration = time.time() - self.stats["start_time"]
        logger.info(f"Capture stopped after {duration:.2f} seconds")
        logger.info(f"Captured {self.stats['packet_count']} packets "
                   f"({self.stats['bytes_captured']} bytes)")
    
    def get_statistics(self) -> Dict[str, Any]:
        current_duration = time.time() - self.stats["start_time"] if self.stats["start_time"] > 0 else 0
        
        pps = self.stats["packet_count"] / current_duration if current_duration > 0 else 0
        
        return {
            **self.stats,
            "duration": current_duration,
            "packets_per_second": pps,
            "bytes_per_second": self.stats["bytes_captured"] / current_duration if current_duration > 0 else 0
        }

