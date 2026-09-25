"""Unit Tests for Packet and Protocol Parsers"""

import pytest
import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pcap_reader import PCAPProcessor
from core.ike_parser import IKEParser
from core.esp_parser import ESPParser
from core.flow_extractor import FlowExtractor


def test_pcap_processor_and_ike_parser():
    pcap_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "testbed", "samples", "scenario_1_enterprise_secure.pcap"
    )
    assert os.path.exists(pcap_path), f"Sample PCAP missing: {pcap_path}"

    proc = PCAPProcessor(pcap_path)
    packets = proc.parse()
    assert len(packets) > 0, "No packets parsed from secure enterprise PCAP"

    raw_packets_dict = [p.to_dict() for p in packets]
    ike_packets_found = 0
    for idx, p in enumerate(packets):
        if p.protocol == "IKE/ISAKMP":
            ike_packets_found += 1
            ike_raw = p.details.get("ike_raw", b"")
            if ike_raw:
                dissected = IKEParser.dissect_packet(ike_raw)
                raw_packets_dict[idx]["ike_details"] = dissected
                assert dissected["major_version"] == 2

    assert ike_packets_found >= 2, "Expected at least 2 IKE handshake packets"

    ike_agg = IKEParser.aggregate_negotiation(raw_packets_dict)
    assert ike_agg.ike_version == "IKEv2.0"
    assert "AES-256-GCM" in ike_agg.encryption_algorithms
    assert ike_agg.has_pfs is True


def test_esp_parser_mode_and_entropy():
    pcap_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "testbed", "samples", "scenario_3_transport_voip.pcap"
    )
    assert os.path.exists(pcap_path)

    proc = PCAPProcessor(pcap_path)
    packets = proc.parse()
    raw_packets_dict = [p.to_dict() for p in packets]

    for idx, p in enumerate(packets):
        if p.protocol == "IKE/ISAKMP":
            ike_raw = p.details.get("ike_raw", b"")
            if ike_raw:
                raw_packets_dict[idx]["ike_details"] = IKEParser.dissect_packet(ike_raw)

    ike_agg = IKEParser.aggregate_negotiation(raw_packets_dict)
    esp_summary = ESPParser.analyze_esp_stream(raw_packets_dict, ike_agg)

    assert esp_summary.packet_count > 100
    assert esp_summary.average_entropy > 6.0  # Max theoretical Shannon entropy in ~140B packet is ~7.1
    assert esp_summary.inferred_mode == "Transport"
    assert len(esp_summary.spis) >= 2


def test_flow_extractor_features():
    pcap_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "testbed", "samples", "scenario_3_transport_voip.pcap"
    )
    proc = PCAPProcessor(pcap_path)
    packets = proc.parse()
    raw_packets_dict = [p.to_dict() for p in packets]

    flow = FlowExtractor.extract_from_packets(raw_packets_dict)
    assert flow.pkt_count > 100
    assert flow.byte_count > 0
    assert flow.len_mean > 50
    assert flow.iat_mean > 0.0
    assert flow.pkt_rate > 0.0
    assert len(flow.to_vector()) == 22
