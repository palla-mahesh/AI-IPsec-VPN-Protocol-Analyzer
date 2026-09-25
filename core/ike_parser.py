"""
IKEv1 and IKEv2 Protocol Dissector
Parses ISAKMP/IKE negotiation exchanges, extracting Security Associations (SAs),
cryptographic proposals, transforms, Diffie-Hellman groups, key lifetimes, and flags.
"""

from typing import List, Dict, Any, Optional, Tuple
import struct

# IKE Exchange Type Mappings
IKEV1_EXCHANGE_TYPES = {
    0: "NONE",
    1: "Base",
    2: "Identity Protection (Main Mode)",
    3: "Authentication Only",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode (Phase 2)",
    33: "New Group Mode"
}

IKEV2_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL"
}

# Next Payload Names
PAYLOAD_TYPES = {
    0: "NONE",
    1: "Security Association (SA)",
    2: "Proposal (P)",
    3: "Transform (T)",
    4: "Key Exchange (KE)",
    5: "Identification (ID)",
    6: "Certificate (CERT)",
    7: "Certificate Request (CR)",
    8: "Hash (HASH)",
    9: "Signature (SIG)",
    10: "Nonce (NONCE)",
    11: "Notification (N)",
    12: "Delete (D)",
    13: "Vendor ID (VID)",
    33: "Security Association (SA v2)",
    34: "Key Exchange (KE v2)",
    35: "Identification Initiator (IDi)",
    36: "Identification Responder (IDr)",
    37: "Certificate (CERT v2)",
    38: "Certificate Request (CR v2)",
    39: "Authentication (AUTH)",
    40: "Nonce (NONCE v2)",
    41: "Notification (N v2)",
    42: "Delete (D v2)",
    43: "Vendor ID (VID v2)",
    44: "Traffic Selector Initiator (TSi)",
    45: "Traffic Selector Responder (TSr)",
    46: "Encrypted & Authenticated (SK)",
    47: "Configuration (CP)",
    48: "Extensible Authentication (EAP)"
}

# Transform Types
IKEV2_TRANSFORM_TYPES = {
    1: "ENCR (Encryption)",
    2: "PRF (Pseudo-Random Function)",
    3: "INTEG (Integrity)",
    4: "D-H (Diffie-Hellman Group)",
    5: "ESN (Extended Sequence Numbers)"
}

# Cryptographic Algorithm ID mappings
ENCRYPTION_ALGORITHMS = {
    1: "DES-CBC",
    2: "IDEA-CBC",
    3: "Blowfish-CBC",
    4: "RC5-R16-B64-CBC",
    5: "3DES-CBC",
    6: "CAST-CBC",
    7: "AES-CBC",
    8: "AES-CTR",
    11: "AES-128-GCM",
    12: "AES-192-GCM",
    13: "AES-256-GCM",
    14: "AES-128-CCM",
    15: "AES-192-CCM",
    16: "AES-256-CCM",
    20: "AES-128-GCM-16",
    28: "ChaCha20-Poly1305"
}

INTEGRITY_ALGORITHMS = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    3: "DES-MAC",
    4: "KPDK-MD5",
    5: "AES-XCBC-MAC",
    8: "HMAC-SHA256-128",
    9: "HMAC-SHA384-192",
    10: "HMAC-SHA512-256",
    12: "AES-128-GMAC",
    13: "AES-192-GMAC",
    14: "AES-256-GMAC"
}

DH_GROUPS = {
    1: "Group 1 (768-bit MODP) [BROKEN]",
    2: "Group 2 (1024-bit MODP) [WEAK]",
    5: "Group 5 (1536-bit MODP) [LEGACY]",
    14: "Group 14 (2048-bit MODP)",
    15: "Group 15 (3072-bit MODP)",
    16: "Group 16 (4096-bit MODP)",
    19: "Group 19 (256-bit Random ECP)",
    20: "Group 20 (384-bit Random ECP)",
    21: "Group 21 (521-bit Random ECP)",
    31: "Curve25519"
}


class IKEDissectionResult:
    def __init__(self):
        self.ike_version: Optional[str] = None
        self.initiator_spi: str = ""
        self.responder_spi: str = ""
        self.exchange_types: List[str] = []
        self.is_aggressive_mode: bool = False
        self.is_main_mode: bool = False
        self.is_ikev2: bool = False
        self.has_pfs: bool = False
        self.nat_traversal_detected: bool = False
        self.proposals: List[Dict[str, Any]] = []
        self.encryption_algorithms: List[str] = []
        self.integrity_algorithms: List[str] = []
        self.dh_groups: List[str] = []
        self.key_lifetimes: List[Dict[str, Any]] = []
        self.vendor_ids: List[str] = []
        self.warnings: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ike_version": self.ike_version or "Unknown",
            "initiator_spi": self.initiator_spi,
            "responder_spi": self.responder_spi,
            "exchange_types": list(set(self.exchange_types)),
            "is_aggressive_mode": self.is_aggressive_mode,
            "is_main_mode": self.is_main_mode,
            "is_ikev2": self.is_ikev2,
            "has_pfs": self.has_pfs,
            "nat_traversal_detected": self.nat_traversal_detected,
            "proposals": self.proposals,
            "encryption_algorithms": list(set(self.encryption_algorithms)),
            "integrity_algorithms": list(set(self.integrity_algorithms)),
            "dh_groups": list(set(self.dh_groups)),
            "key_lifetimes": self.key_lifetimes,
            "vendor_ids": list(set(self.vendor_ids)),
            "warnings": list(set(self.warnings))
        }


class IKEParser:
    """Robust parser for IKEv1 and IKEv2 packets."""

    @staticmethod
    def dissect_packet(raw_data: bytes, is_nat_t: bool = False) -> Optional[Dict[str, Any]]:
        """Dissects an IKE packet header and payloads from raw bytes."""
        if is_nat_t and raw_data.startswith(b'\x00\x00\x00\x00'):
            # Strip 4-byte Non-ESP marker for NAT-T UDP 4500
            raw_data = raw_data[4:]

        if len(raw_data) < 28:
            return None

        # ISAKMP Header:
        # Initiator SPI (8 bytes) + Responder SPI (8 bytes) + Next Payload (1 byte)
        # + Version (1 byte: Maj:Min 4-bit nibbles) + Exchange Type (1 byte)
        # + Flags (1 byte) + Message ID (4 bytes) + Length (4 bytes)
        i_spi, r_spi, next_payload, ver_byte, exch_type, flags, msg_id, total_len = struct.unpack(
            "!8s8sBBBBI I", raw_data[:28]
        )

        major_ver = (ver_byte >> 4) & 0x0F
        minor_ver = ver_byte & 0x0F
        ike_version_str = f"IKEv{major_ver}.{minor_ver}"

        is_initiator = bool(flags & 0x08)
        is_response = bool(flags & 0x20)

        exchange_name = "Unknown"
        if major_ver == 1:
            exchange_name = IKEV1_EXCHANGE_TYPES.get(exch_type, f"IKEv1-Exch-{exch_type}")
        elif major_ver == 2:
            exchange_name = IKEV2_EXCHANGE_TYPES.get(exch_type, f"IKEv2-Exch-{exch_type}")

        header_info = {
            "ike_version": ike_version_str,
            "major_version": major_ver,
            "minor_version": minor_ver,
            "initiator_spi": f"0x{i_spi.hex()}",
            "responder_spi": f"0x{r_spi.hex()}",
            "next_payload": PAYLOAD_TYPES.get(next_payload, f"Payload-{next_payload}"),
            "next_payload_id": next_payload,
            "exchange_type": exchange_name,
            "exchange_type_id": exch_type,
            "flags": {
                "initiator": is_initiator,
                "response": is_response,
                "raw": flags
            },
            "msg_id": msg_id,
            "length": total_len,
            "payloads": []
        }

        # Parse payloads recursively
        payload_offset = 28
        curr_payload_id = next_payload

        while curr_payload_id != 0 and payload_offset < len(raw_data):
            if payload_offset + 4 > len(raw_data):
                break
            nxt_p, p_reserved, p_len = struct.unpack("!BBH", raw_data[payload_offset:payload_offset+4])
            if p_len < 4 or payload_offset + p_len > len(raw_data):
                p_len = len(raw_data) - payload_offset  # Clamp to remaining
                
            payload_data = raw_data[payload_offset+4:payload_offset+p_len]
            p_dict = {
                "id": curr_payload_id,
                "name": PAYLOAD_TYPES.get(curr_payload_id, f"Payload-{curr_payload_id}"),
                "length": p_len
            }

            # SA Payload Parsing
            if curr_payload_id in (1, 33):  # SA v1 or v2
                sa_details = IKEParser._parse_sa_payload(payload_data, major_ver)
                p_dict["sa_details"] = sa_details
            # Key Exchange Payload
            elif curr_payload_id in (4, 34):  # KE v1 or v2
                if major_ver == 2 and len(payload_data) >= 4:
                    dh_grp, _ = struct.unpack("!HH", payload_data[:4])
                    p_dict["dh_group_id"] = dh_grp
                    p_dict["dh_group"] = DH_GROUPS.get(dh_grp, f"DH-Group-{dh_grp}")
                    p_dict["key_exchange_data_len"] = len(payload_data) - 4
                else:
                    p_dict["key_exchange_data_len"] = len(payload_data)
            # Identification
            elif curr_payload_id in (5, 35, 36):
                p_dict["id_payload_len"] = len(payload_data)

            header_info["payloads"].append(p_dict)
            curr_payload_id = nxt_p
            payload_offset += p_len

        return header_info

    @staticmethod
    def _parse_sa_payload(sa_data: bytes, major_version: int) -> Dict[str, Any]:
        """Parses proposals and transforms inside an SA payload."""
        result = {"proposals": []}
        if len(sa_data) < 4:
            return result

        # In IKEv1, first 4 bytes is DOI (Domain of Interpretation) usually 1 (IPsec)
        # + Situation (4 bytes)
        offset = 8 if major_version == 1 else 0

        while offset + 8 <= len(sa_data):
            p_next, _, p_len, p_num, proto_id, spi_sz, num_transforms = struct.unpack(
                "!BBHBBBB", sa_data[offset:offset+8]
            )
            if p_len < 8:
                break
            
            p_data = sa_data[offset+8:offset+p_len]
            spi = p_data[:spi_sz].hex() if spi_sz > 0 else ""
            
            proposal_dict = {
                "proposal_number": p_num,
                "protocol": "IKE" if proto_id == 1 else ("AH" if proto_id == 2 else "ESP"),
                "spi": spi,
                "transforms": []
            }

            # Parse Transforms
            t_offset = spi_sz
            while t_offset + 8 <= len(p_data):
                if major_version == 1:
                    t_next, _, t_len, t_num, t_id = struct.unpack("!BBHBB", p_data[t_offset:t_offset+6])
                    if t_len < 8:
                        break
                    t_body = p_data[t_offset+8:t_offset+t_len]
                    transform_dict = {
                        "transform_number": t_num,
                        "transform_id": t_id,
                        "attributes": {}
                    }
                    transform_dict["encryption"] = ENCRYPTION_ALGORITHMS.get(t_id, f"Cipher-{t_id}")
                    # Parse IKEv1 Attributes
                    attr_offset = 0
                    while attr_offset + 4 <= len(t_body):
                        af_type, attr_val = struct.unpack("!HH", t_body[attr_offset:attr_offset+4])
                        is_tv = bool(af_type & 0x8000)
                        attr_type = af_type & 0x7FFF
                        if is_tv:
                            transform_dict["attributes"][attr_type] = attr_val
                            if attr_type == 1:
                                transform_dict["encryption"] = ENCRYPTION_ALGORITHMS.get(attr_val, f"Algo-{attr_val}")
                            elif attr_type == 2:
                                transform_dict["integrity"] = INTEGRITY_ALGORITHMS.get(attr_val, f"Hash-{attr_val}")
                            elif attr_type == 4:
                                transform_dict["dh_group"] = DH_GROUPS.get(attr_val, f"DH-{attr_val}")
                                transform_dict["dh_group_id"] = attr_val
                            elif attr_type == 14:
                                transform_dict["key_length"] = attr_val
                            elif attr_type == 11:
                                transform_dict["life_type"] = "seconds" if attr_val == 1 else "kilobytes"
                            elif attr_type == 12:
                                transform_dict["life_duration"] = attr_val
                            attr_offset += 4
                        else:
                            attr_len = attr_val
                            attr_offset += 4 + attr_len
                    proposal_dict["transforms"].append(transform_dict)
                    t_offset += t_len
                    if t_next == 0:
                        break
                else:
                    # IKEv2 Transform Header (RFC 7296 Section 3.3.2)
                    t_last, _, t_len, t_type, _, t_id = struct.unpack("!BBHBBH", p_data[t_offset:t_offset+8])
                    if t_len < 8:
                        break
                    transform_dict = {
                        "type_id": t_type,
                        "type_name": IKEV2_TRANSFORM_TYPES.get(t_type, f"Type-{t_type}"),
                        "transform_id": t_id,
                        "attributes": {}
                    }
                    if t_type == 1:  # ENCR
                        transform_dict["encryption"] = ENCRYPTION_ALGORITHMS.get(t_id, f"ENCR-{t_id}")
                    elif t_type == 2:  # PRF
                        transform_dict["prf"] = INTEGRITY_ALGORITHMS.get(t_id, f"PRF-{t_id}")
                    elif t_type == 3:  # INTEG
                        transform_dict["integrity"] = INTEGRITY_ALGORITHMS.get(t_id, f"INTEG-{t_id}")
                    elif t_type == 4:  # D-H
                        transform_dict["dh_group"] = DH_GROUPS.get(t_id, f"DH-{t_id}")
                        transform_dict["dh_group_id"] = t_id
                    elif t_type == 5:  # ESN
                        transform_dict["esn"] = "ESN" if t_id == 1 else "No ESN"

                    proposal_dict["transforms"].append(transform_dict)
                    t_offset += t_len
                    if t_last == 0:
                        break

            result["proposals"].append(proposal_dict)
            offset += p_len
            if p_next == 0:
                break

        return result

    @staticmethod
    def aggregate_negotiation(parsed_packets: List[Dict[str, Any]]) -> IKEDissectionResult:
        """Aggregates all parsed IKE packets in a session into a cohesive summary."""
        res = IKEDissectionResult()

        for pkt in parsed_packets:
            if not pkt.get("ike_details"):
                continue
            details = pkt["ike_details"]
            
            if details.get("ike_version") and not res.ike_version:
                res.ike_version = details["ike_version"]
                res.is_ikev2 = (details.get("major_version") == 2)
            
            if details.get("initiator_spi") and not res.initiator_spi:
                res.initiator_spi = details["initiator_spi"]
            if details.get("responder_spi") and not res.responder_spi:
                res.responder_spi = details["responder_spi"]

            exch = details.get("exchange_type", "")
            res.exchange_types.append(exch)
            if "Aggressive" in exch:
                res.is_aggressive_mode = True
                res.warnings.append("IKEv1 Aggressive Mode in use: Pre-Shared Key hash is exposed to offline dictionary cracking.")
            if "Main Mode" in exch or "Identity Protection" in exch:
                res.is_main_mode = True

            # Process Payloads
            for p in details.get("payloads", []):
                p_name = p.get("name", "")
                if "Vendor ID" in p_name:
                    res.vendor_ids.append(p_name)
                    if "NAT-T" in p_name:
                        res.nat_traversal_detected = True
                
                # DH from KE payload
                if p.get("dh_group"):
                    res.dh_groups.append(p["dh_group"])
                    res.has_pfs = True  # KE exchanged in child SA or phase 2 implies PFS

                # SA details
                if p.get("sa_details"):
                    sa = p["sa_details"]
                    for prop in sa.get("proposals", []):
                        res.proposals.append(prop)
                        for tf in prop.get("transforms", []):
                            if tf.get("encryption"):
                                enc = tf["encryption"]
                                res.encryption_algorithms.append(enc)
                                if "3DES" in enc or "DES" in enc or "Blowfish" in enc:
                                    res.warnings.append(f"Insecure/Legacy cipher proposed: {enc} (Sweet32 64-bit vulnerability).")
                            if tf.get("integrity"):
                                hmac = tf["integrity"]
                                res.integrity_algorithms.append(hmac)
                                if "MD5" in hmac:
                                    res.warnings.append("Broken integrity algorithm proposed: HMAC-MD5 (practical collision attacks).")
                                elif "SHA1" in hmac:
                                    res.warnings.append("Weak integrity algorithm proposed: HMAC-SHA1.")
                            if tf.get("dh_group"):
                                dh = tf["dh_group"]
                                res.dh_groups.append(dh)
                                dh_id = tf.get("dh_group_id", 0)
                                if dh_id in (1, 2):
                                    res.warnings.append(f"Vulnerable Diffie-Hellman group: {dh} (<2048-bit MODP, vulnerable to Logjam precomputation).")
                            if tf.get("life_duration"):
                                res.key_lifetimes.append({
                                    "type": tf.get("life_type", "seconds"),
                                    "duration": tf["life_duration"]
                                })

        return res
