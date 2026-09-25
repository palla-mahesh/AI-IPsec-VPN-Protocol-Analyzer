"""Unit Tests for Security Assessment & Compliance Engine"""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pcap_reader import PCAPProcessor
from core.ike_parser import IKEParser
from core.esp_parser import ESPParser
from core.flow_extractor import FlowExtractor
from core.security_engine import SecurityEngine


def test_secure_enterprise_evaluation():
    pcap_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "testbed", "samples", "scenario_1_enterprise_secure.pcap"
    )
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
    flow = FlowExtractor.extract_from_packets(raw_packets_dict)

    sec_engine = SecurityEngine()
    result = sec_engine.assess(ike_agg, esp_summary, flow)

    assert result.overall_score >= 85, f"Expected secure score, got {result.overall_score}"
    assert result.risk_level == "SECURE"
    assert result.compliance_status["NIST_SP_800_77_Rev1"] is True
    assert result.compliance_status["RFC_8221_ESP"] is True
    assert len(result.threat_matrix) == 0


def test_legacy_vulnerable_evaluation():
    pcap_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "testbed", "samples", "scenario_2_legacy_vulnerable.pcap"
    )
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
    flow = FlowExtractor.extract_from_packets(raw_packets_dict)

    sec_engine = SecurityEngine()
    result = sec_engine.assess(ike_agg, esp_summary, flow)

    assert result.overall_score < 50, f"Expected high risk score, got {result.overall_score}"
    assert result.risk_level in ("HIGH RISK", "CRITICAL RISK")
    assert result.compliance_status["NIST_SP_800_77_Rev1"] is False

    threat_ids = [t.threat_id for t in result.threat_matrix]
    assert "SEC-CIPHER-001" in threat_ids  # Sweet32 3DES
    assert "SEC-HASH-001" in threat_ids    # Broken MD5
    assert "SEC-DH-001" in threat_ids      # Broken DH Group 1
    assert "SEC-PFS-001" in threat_ids     # Missing PFS
