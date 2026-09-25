"""Integration Tests for FastAPI Web Service and REST Endpoints"""

import pytest
import os
import sys
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app import app

client = TestClient(app)


def test_index_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "AI-Powered IPsec VPN Protocol Analyzer" in response.text


def test_list_scenarios():
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert "scenarios" in data
    assert len(data["scenarios"]) >= 5


def test_run_scenario_endpoint():
    response = client.post(
        "/api/scenarios/run",
        data={"scenario_name": "scenario_1_enterprise_secure.pcap"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["packet_count"] > 0
    assert "security_assessment" in data
    assert "ai_classification" in data
    assert data["security_assessment"]["overall_score"] >= 85


def test_generate_custom_testbed_endpoint():
    response = client.post(
        "/api/testbed/generate",
        data={
            "scenario_name": "test_api_voip",
            "ike_version": 2,
            "mode": "Transport",
            "cipher": "AES-128-CBC",
            "integrity": "HMAC-SHA256",
            "dh_group": 14,
            "pfs_enabled": True,
            "traffic_type": "VoIP",
            "packet_count": 50
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["packet_count"] >= 50
    assert data["esp_summary"]["inferred_mode"] == "Transport"
    assert data["ai_classification"]["predicted_class"] == "VoIP"


def test_download_reports():
    # Run scenario first to populate report paths
    client.post(
        "/api/scenarios/run",
        data={"scenario_name": "scenario_1_enterprise_secure.pcap"}
    )
    resp_exec = client.get("/api/report/executive")
    assert resp_exec.status_code == 200
    assert "Executive Security Assessment" in resp_exec.text

    resp_tech = client.get("/api/report/technical")
    assert resp_tech.status_code == 200
    assert "Technical Protocol Audit" in resp_tech.text
