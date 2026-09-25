"""
ESP (Encapsulating Security Payload) & AH (Authentication Header) Dissector
Analyzes SPIs, sequence numbers, replay windows, payload entropy, and infers
operating modes (Tunnel vs Transport).
"""

from typing import List, Dict, Any, Tuple, Optional
import math
import struct


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


class ESPDissectionSummary:
    def __init__(self):
        self.spis: List[str] = []
        self.packet_count: int = 0
        self.total_bytes: int = 0
        self.min_seq: int = 0
        self.max_seq: int = 0
        self.sequence_gaps: int = 0
        self.replay_errors: int = 0
        self.average_entropy: float = 0.0
        self.inferred_mode: str = "Tunnel"  # Default in enterprise/defense
        self.mode_confidence: float = 0.85
        self.mode_reasoning: List[str] = []
        self.packet_sizes: List[int] = []
        self.timestamps: List[float] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spis": list(set(self.spis)),
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "min_seq": self.min_seq,
            "max_seq": self.max_seq,
            "sequence_gaps": self.sequence_gaps,
            "replay_errors": self.replay_errors,
            "average_entropy": round(self.average_entropy, 3),
            "inferred_mode": self.inferred_mode,
            "mode_confidence": round(self.mode_confidence, 2),
            "mode_reasoning": self.mode_reasoning,
            "packet_sizes": self.packet_sizes[:100],  # preview
            "packet_count_evaluated": len(self.packet_sizes)
        }


class ESPParser:
    """Parser and flow analyzer for IPsec ESP and AH traffic."""

    @staticmethod
    def dissect_esp_packet(raw_bytes: bytes, offset: int = 0) -> Dict[str, Any]:
        """Dissects an ESP packet header from raw IP payload."""
        data = raw_bytes[offset:]
        if len(data) < 8:
            return {"error": "Truncated ESP packet"}

        spi, seq = struct.unpack("!II", data[:8])
        payload = data[8:]
        entropy = calculate_entropy(payload)

        return {
            "spi": f"0x{spi:08x}",
            "spi_int": spi,
            "seq": seq,
            "payload_len": len(payload),
            "entropy": entropy,
            "is_encrypted": entropy > 7.5
        }

    @staticmethod
    def analyze_esp_stream(
        packets: List[Dict[str, Any]],
        ike_negotiation: Optional[Any] = None
    ) -> ESPDissectionSummary:
        """Analyzes a collection of parsed ESP packets to infer mode, integrity, and replay health."""
        summary = ESPDissectionSummary()
        esp_packets = [p for p in packets if p.get("protocol") in ("ESP", "ESP-in-UDP")]

        if not esp_packets:
            return summary

        summary.packet_count = len(esp_packets)
        entropies = []
        seq_nums_by_spi: Dict[str, List[int]] = {}

        for p in esp_packets:
            details = p.get("details", {})
            length = p.get("length", 0)
            summary.total_bytes += length
            summary.packet_sizes.append(length)
            summary.timestamps.append(p.get("timestamp", 0.0))

            spi = details.get("spi", "0x00000000")
            summary.spis.append(spi)

            seq = details.get("seq", 0)
            if spi not in seq_nums_by_spi:
                seq_nums_by_spi[spi] = []
            seq_nums_by_spi[spi].append(seq)

            # Entropy calculation
            if "entropy" in details and details["entropy"] > 0.0:
                entropies.append(details["entropy"])
            elif details.get("esp_payload_hex"):
                payload_bytes = bytes.fromhex(details["esp_payload_hex"])
                entropies.append(calculate_entropy(payload_bytes))
            elif p.get("raw_bytes"):
                raw = p["raw_bytes"]
                if len(raw) > 34:
                    entropies.append(calculate_entropy(raw[34:]))
            elif p.get("hex_preview"):
                raw = bytes.fromhex(p["hex_preview"])
                if len(raw) > 34:
                    entropies.append(calculate_entropy(raw[34:]))

        if entropies:
            summary.average_entropy = sum(entropies) / len(entropies)

        # Anti-replay & Sequence number auditing
        all_seqs = []
        for spi, seqs in seq_nums_by_spi.items():
            all_seqs.extend(seqs)
            # Check for sequence duplicates
            seen = set()
            for s in seqs:
                if s in seen:
                    summary.replay_errors += 1
                seen.add(s)

            # Check gaps
            sorted_seqs = sorted(seqs)
            if sorted_seqs:
                expected = sorted_seqs[-1] - sorted_seqs[0] + 1
                actual = len(set(sorted_seqs))
                summary.sequence_gaps += max(0, expected - actual)

        if all_seqs:
            summary.min_seq = min(all_seqs)
            summary.max_seq = max(all_seqs)

        # Mode Inference (Tunnel Mode vs Transport Mode)
        ESPParser._infer_mode(summary, esp_packets, ike_negotiation)

        return summary

    @staticmethod
    def _infer_mode(
        summary: ESPDissectionSummary,
        esp_packets: List[Dict[str, Any]],
        ike_negotiation: Optional[Any]
    ) -> None:
        """Infers Tunnel vs Transport mode using IKE proposals and flow properties."""
        tunnel_score = 0
        transport_score = 0
        reasons = []

        # 1. Check IKE proposals if available
        if ike_negotiation and hasattr(ike_negotiation, "proposals"):
            for prop in ike_negotiation.proposals:
                for tf in prop.get("transforms", []):
                    attrs = tf.get("attributes", {})
                    # Attribute 4 in IPsec DOI = Encapsulation Mode (1 = Tunnel, 2 = Transport)
                    encap = attrs.get(4)
                    if encap == 1:
                        tunnel_score += 40
                        reasons.append("IKE SA Proposal explicitly specifies Encapsulation Mode 1 (Tunnel Mode).")
                    elif encap == 2:
                        transport_score += 40
                        reasons.append("IKE SA Proposal explicitly specifies Encapsulation Mode 2 (Transport Mode).")

        # 2. Check IP Endpoint relationships
        ike_ips = set()
        esp_ips = set()
        for p in esp_packets:
            esp_ips.add((p.get("src_ip"), p.get("dst_ip")))

        # Check packet size distribution (Tunnel Mode has extra inner IP header: 20 bytes for IPv4, 40 bytes for IPv6)
        if summary.packet_sizes:
            avg_size = sum(summary.packet_sizes) / len(summary.packet_sizes)
            # Common MTU with Tunnel overhead (ESP header 8B + IV 16B + Pad 0-15B + ICV 16B + Inner IP 20B = ~60B overhead)
            max_size = max(summary.packet_sizes)
            if max_size >= 1400:
                tunnel_score += 15
                reasons.append(f"Payload sizes (max {max_size}B) conform to gateway tunnel MTU encapsulation.")
            
            # Transport mode often seen with host-to-host direct port communications or smaller fixed MTU
            if avg_size < 200 and all(s < 300 for s in summary.packet_sizes):
                transport_score += 10
                reasons.append("Small homogeneous packet lengths consistent with host-level transport traffic.")

        # Default heuristic based on weights
        if transport_score > tunnel_score:
            summary.inferred_mode = "Transport"
            confidence = min(0.98, 0.65 + (transport_score - tunnel_score) * 0.01)
        else:
            summary.inferred_mode = "Tunnel"
            confidence = min(0.98, 0.70 + (tunnel_score - transport_score) * 0.01)

        summary.mode_confidence = confidence
        summary.mode_reasoning = reasons or ["Inferred from standard IPsec Gateway encapsulation overhead."]
