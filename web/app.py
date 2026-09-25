"""
FastAPI Application & REST Backend
Provides endpoints for PCAP uploads, real-time protocol analysis, AI classification,
security compliance auditing, testbed generation, and report downloading.
"""

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List, Optional
import os
import shutil
import tempfile

from core.pcap_reader import PCAPProcessor
from core.ike_parser import IKEParser
from core.esp_parser import ESPParser
from core.flow_extractor import FlowExtractor
from core.security_engine import SecurityEngine
from ml.classifier import IPsecTrafficClassifier
from testbed.traffic_generator import IPsecTrafficGenerator
from reports.generator import ReportGenerator

app = FastAPI(
    title="AI-Powered IPsec VPN Protocol Analyzer",
    description="Automated IPsec Protocol Inspection, Security Assessment & Encrypted Traffic Inference Platform (NTRO Problem 26160)",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
classifier = IPsecTrafficClassifier()
sec_engine = SecurityEngine()
report_gen = ReportGenerator()
generator = IPsecTrafficGenerator()

# Cache latest assessment for instant report generation
LATEST_ANALYSIS: Dict[str, Any] = {}


def run_full_analysis(pcap_path: str, filename: str = "uploaded.pcap") -> Dict[str, Any]:
    """Runs the complete analysis pipeline on a PCAP file."""
    proc = PCAPProcessor(pcap_path)
    packets = proc.parse()
    raw_packets_dict = [p.to_dict() for p in packets]

    for idx, p in enumerate(packets):
        if p.protocol == "IKE/ISAKMP":
            ike_raw = p.details.get("ike_raw", b"")
            if ike_raw:
                dissected = IKEParser.dissect_packet(ike_raw)
                raw_packets_dict[idx]["ike_details"] = dissected

    ike_agg = IKEParser.aggregate_negotiation(raw_packets_dict)
    esp_summary = ESPParser.analyze_esp_stream(raw_packets_dict, ike_agg)
    flow_feats = FlowExtractor.extract_from_packets(raw_packets_dict)
    ai_result = classifier.predict(flow_feats)
    sec_result = sec_engine.assess(ike_agg, esp_summary, flow_feats)

    analysis = {
        "filename": filename,
        "packet_count": len(packets),
        "ike_negotiation": ike_agg.to_dict(),
        "esp_summary": esp_summary.to_dict(),
        "flow_features": flow_feats.to_dict(),
        "ai_classification": ai_result.to_dict(),
        "security_assessment": sec_result.to_dict(),
        "packets_preview": [p.to_dict() for p in packets[:60]]  # first 60 for inspector
    }

    # Generate and store reports
    paths = report_gen.generate_all(analysis, scenario_name=os.path.splitext(filename)[0])
    analysis["report_paths"] = paths
    global LATEST_ANALYSIS
    LATEST_ANALYSIS = analysis

    return analysis


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>IPsec VPN Protocol Analyzer API Ready</h1>"


@app.get("/api/scenarios")
async def list_scenarios():
    """Lists available pre-generated benchmark PCAP scenarios."""
    samples_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "testbed", "samples"
    )
    if not os.path.exists(samples_dir):
        return {"scenarios": []}
    files = [f for f in os.listdir(samples_dir) if f.endswith(".pcap")]
    return {"scenarios": sorted(files)}


@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """Upload and analyze a custom PCAP file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        result = run_full_analysis(tmp_path, filename=file.filename or "uploaded.pcap")
        return JSONResponse(content=result)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.post("/api/scenarios/run")
async def run_scenario(scenario_name: str = Form(...)):
    """Analyzes a built-in benchmark scenario PCAP."""
    samples_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "testbed", "samples"
    )
    pcap_path = os.path.join(samples_dir, scenario_name)
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail=f"Scenario {scenario_name} not found")

    result = run_full_analysis(pcap_path, filename=scenario_name)
    return JSONResponse(content=result)


@app.post("/api/testbed/generate")
async def generate_custom_testbed(
    scenario_name: str = Form("custom_testbed"),
    ike_version: int = Form(2),
    mode: str = Form("Tunnel"),
    cipher: str = Form("AES-256-GCM"),
    integrity: Optional[str] = Form(None),
    dh_group: int = Form(19),
    pfs_enabled: bool = Form(True),
    traffic_type: str = Form("Web"),
    packet_count: int = Form(100)
):
    """Generates a custom PCAP with specific parameters and analyzes it immediately."""
    pcap_path = generator.generate_scenario(
        scenario_name=scenario_name,
        ike_version=ike_version,
        mode=mode,
        cipher=cipher,
        integrity=integrity,
        dh_group=dh_group,
        pfs_enabled=pfs_enabled,
        traffic_type=traffic_type,
        packet_count=packet_count
    )
    result = run_full_analysis(pcap_path, filename=os.path.basename(pcap_path))
    return JSONResponse(content=result)


@app.get("/api/report/executive")
async def download_executive_report():
    if not LATEST_ANALYSIS or "report_paths" not in LATEST_ANALYSIS:
        raise HTTPException(status_code=400, detail="No active analysis available. Run an audit first.")
    path = LATEST_ANALYSIS["report_paths"]["executive_html"]
    return FileResponse(path, media_type="text/html", filename="IPsec_Executive_Security_Report.html")


@app.get("/api/report/technical")
async def download_technical_report():
    if not LATEST_ANALYSIS or "report_paths" not in LATEST_ANALYSIS:
        raise HTTPException(status_code=400, detail="No active analysis available. Run an audit first.")
    path = LATEST_ANALYSIS["report_paths"]["technical_html"]
    return FileResponse(path, media_type="text/html", filename="IPsec_Technical_Audit_Report.html")


@app.get("/api/report/json")
async def download_json_report():
    if not LATEST_ANALYSIS or "report_paths" not in LATEST_ANALYSIS:
        raise HTTPException(status_code=400, detail="No active analysis available. Run an audit first.")
    path = LATEST_ANALYSIS["report_paths"]["audit_json"]
    return FileResponse(path, media_type="application/json", filename="IPsec_Security_Audit.json")
