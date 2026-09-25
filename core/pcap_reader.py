"""
PCAP & Network Stream Ingestor
Reads PCAP/PCAPNG files, parses network packets, and extracts IPsec relevant protocol layers.
"""

from typing import List, Dict, Any, Generator, Optional
import os
import struct
import math

try:
    from scapy.all import rdpcap, PcapReader, IP, IPv6, UDP, Raw
    from scapy.layers.ipsec import ESP, AH
    from scapy.layers.isakmp import ISAKMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of raw byte data in bits per byte (max 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p_x = float(count) / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


class PacketInfo:
    def __init__(
        self,
        index: int,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        ip_version: int,
        protocol: str,
        length: int,
        summary: str,
        raw_bytes: bytes,
        layers: List[str],
        details: Dict[str, Any]
    ):
        self.index = index
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ip_version = ip_version
        self.protocol = protocol
        self.length = length
        self.summary = summary
        self.raw_bytes = raw_bytes
        self.layers = layers
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        clean_details = {}
        for k, v in self.details.items():
            if isinstance(v, bytes):
                clean_details[k] = v.hex()
            else:
                clean_details[k] = v

        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ip_version": self.ip_version,
            "protocol": self.protocol,
            "length": self.length,
            "summary": self.summary,
            "layers": self.layers,
            "details": clean_details,
            "hex_preview": self.raw_bytes[:64].hex() if self.raw_bytes else ""
        }


class PCAPProcessor:
    """Processes network PCAP files and extracts IPsec protocol exchanges."""

    def __init__(self, filepath: str):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        self.filepath = filepath
        self.packets: List[PacketInfo] = []

    def parse(self, max_packets: Optional[int] = None) -> List[PacketInfo]:
        """Parses the PCAP file and returns a list of PacketInfo objects."""
        self.packets = []
        if not SCAPY_AVAILABLE:
            # Fallback pure-python basic parser if scapy is initializing
            return self._parse_pure_python(max_packets)

        scapy_packets = rdpcap(self.filepath)
        for idx, pkt in enumerate(scapy_packets):
            if max_packets and idx >= max_packets:
                break
            
            pinfo = self._process_scapy_packet(idx + 1, pkt)
            if pinfo:
                self.packets.append(pinfo)
                
        return self.packets

    def _process_scapy_packet(self, index: int, pkt) -> Optional[PacketInfo]:
        timestamp = float(pkt.time)
        length = len(pkt)
        raw_bytes = bytes(pkt)
        
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        ip_version = 4
        protocol = "UNKNOWN"
        layers = []
        details = {}

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_version = 4
            proto_num = pkt[IP].proto
            layers.append("IPv4")
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            ip_version = 6
            proto_num = pkt[IPv6].nh
            layers.append("IPv6")
        else:
            proto_num = None

        # Check for IKE (ISAKMP) - UDP 500 or 4500 (NAT-Traversal)
        if pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            layers.append("UDP")
            details["sport"] = udp_layer.sport
            details["dport"] = udp_layer.dport
            
            if udp_layer.sport in (500, 4500) or udp_layer.dport in (500, 4500):
                protocol = "IKE/ISAKMP"
                layers.append("IKE")
                
                # Check for Non-ESP Marker in UDP 4500 (4 zero bytes before IKE)
                udp_payload = bytes(udp_layer.payload)
                if udp_layer.sport == 4500 or udp_layer.dport == 4500:
                    details["nat_traversal"] = True
                    if udp_payload.startswith(b'\x00\x00\x00\x00'):
                        details["non_esp_marker"] = True
                        details["ike_raw"] = udp_payload[4:]
                    else:
                        # Direct ESP encapsulated in UDP 4500
                        protocol = "ESP-in-UDP"
                        details["esp_raw"] = udp_payload
                else:
                    details["ike_raw"] = udp_payload

        # Check for direct ESP (IP proto 50)
        if proto_num == 50 or pkt.haslayer(ESP):
            protocol = "ESP"
            layers.append("ESP")
            if pkt.haslayer(ESP):
                details["spi"] = f"0x{pkt[ESP].spi:08x}"
                details["seq"] = pkt[ESP].seq
                esp_data = bytes(pkt[ESP].data)
                details["data_len"] = len(esp_data)
                details["entropy"] = calculate_entropy(esp_data)
            else:
                # Raw ESP byte parsing
                esp_raw = bytes(pkt[IP].payload) if pkt.haslayer(IP) else bytes(pkt.payload)
                if len(esp_raw) >= 8:
                    spi_val, seq_val = struct.unpack("!II", esp_raw[:8])
                    details["spi"] = f"0x{spi_val:08x}"
                    details["seq"] = seq_val
                    esp_data = esp_raw[8:]
                    details["data_len"] = len(esp_data)
                    details["entropy"] = calculate_entropy(esp_data)

        # Check for AH (IP proto 51)
        elif proto_num == 51 or pkt.haslayer(AH):
            protocol = "AH"
            layers.append("AH")
            if pkt.haslayer(AH):
                details["spi"] = f"0x{pkt[AH].spi:08x}"
                details["seq"] = pkt[AH].seq

        summary = f"{protocol} {src_ip} -> {dst_ip} (Len: {length})"
        
        return PacketInfo(
            index=index,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=ip_version,
            protocol=protocol,
            length=length,
            summary=summary,
            raw_bytes=raw_bytes,
            layers=layers,
            details=details
        )

    def _parse_pure_python(self, max_packets: Optional[int] = None) -> List[PacketInfo]:
        """Pure Python fallback for pcap files using binary struct parsing."""
        packets = []
        with open(self.filepath, "rb") as f:
            header = f.read(24)
            if len(header) < 24:
                return packets
            magic = header[:4]
            if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                return packets  # Not standard pcap
            
            idx = 0
            while True:
                if max_packets and idx >= max_packets:
                    break
                rec_hdr = f.read(16)
                if len(rec_hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack("IIII", rec_hdr)
                pkt_data = f.read(incl_len)
                idx += 1
                
                # Ethernet frame (14 bytes)
                eth_proto = struct.unpack("!H", pkt_data[12:14])[0] if len(pkt_data) >= 14 else 0
                ip_version = 4
                src_ip = "0.0.0.0"
                dst_ip = "0.0.0.0"
                protocol = "RAW"
                details = {}
                layers = ["Ethernet"]
                
                if eth_proto == 0x0800 and len(pkt_data) >= 34:  # IPv4
                    ip_hdr = pkt_data[14:34]
                    proto = ip_hdr[9]
                    src_ip = ".".join(str(b) for b in ip_hdr[12:16])
                    dst_ip = ".".join(str(b) for b in ip_hdr[16:20])
                    layers.append("IPv4")
                    
                    if proto == 50:
                        protocol = "ESP"
                        layers.append("ESP")
                        if len(pkt_data) >= 42:
                            spi, seq = struct.unpack("!II", pkt_data[34:42])
                            details["spi"] = f"0x{spi:08x}"
                            details["seq"] = seq
                    elif proto == 17:  # UDP
                        layers.append("UDP")
                        sport, dport = struct.unpack("!HH", pkt_data[34:38])
                        details["sport"] = sport
                        details["dport"] = dport
                        if sport in (500, 4500) or dport in (500, 4500):
                            protocol = "IKE/ISAKMP"
                            layers.append("IKE")
                            details["ike_raw"] = pkt_data[42:]
                            
                packets.append(PacketInfo(
                    index=idx,
                    timestamp=float(ts_sec) + float(ts_usec) / 1000000.0,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ip_version=ip_version,
                    protocol=protocol,
                    length=incl_len,
                    summary=f"{protocol} {src_ip} -> {dst_ip}",
                    raw_bytes=pkt_data,
                    layers=layers,
                    details=details
                ))
        return packets
