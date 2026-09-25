"""
Automated Report Generator
Generates Executive Summary Reports and Deep Technical Audit Reports in
HTML, JSON, and Markdown formats for IPsec VPN security assessments.
"""

from typing import Dict, Any, List, Optional
import os
import json
import datetime


class ReportGenerator:
    """Generates standardized Executive and Technical audit reports."""

    def __init__(self, output_dir: str = "reports/generated"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_all(
        self,
        analysis_data: Dict[str, Any],
        scenario_name: str = "IPsec_VPN_Assessment"
    ) -> Dict[str, str]:
        """Generates both executive and technical reports in HTML and JSON."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{scenario_name}_{timestamp}"

        exec_html_path = os.path.join(self.output_dir, f"{base_name}_executive.html")
        tech_html_path = os.path.join(self.output_dir, f"{base_name}_technical.html")
        json_path = os.path.join(self.output_dir, f"{base_name}_audit.json")

        exec_html = self.build_executive_html(analysis_data)
        tech_html = self.build_technical_html(analysis_data)

        with open(exec_html_path, "w", encoding="utf-8") as f:
            f.write(exec_html)

        with open(tech_html_path, "w", encoding="utf-8") as f:
            f.write(tech_html)

        def json_serial(obj):
            if isinstance(obj, bytes):
                return obj.hex()
            raise TypeError(f"Type {type(obj)} not serializable")

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(analysis_data, f, indent=2, default=json_serial)

        return {
            "executive_html": exec_html_path,
            "technical_html": tech_html_path,
            "audit_json": json_path
        }

    def build_executive_html(self, data: Dict[str, Any]) -> str:
        score = data.get("security_assessment", {}).get("overall_score", 0)
        risk = data.get("security_assessment", {}).get("risk_level", "UNKNOWN")
        ai_pred = data.get("ai_classification", {}).get("predicted_class", "Unknown")
        ai_conf = data.get("ai_classification", {}).get("confidence_score", 0.0)
        mode = data.get("esp_summary", {}).get("inferred_mode", "Tunnel")
        ike_ver = data.get("ike_negotiation", {}).get("ike_version", "Unknown")
        ciphers = ", ".join(data.get("ike_negotiation", {}).get("encryption_algorithms", ["None"])) or "None"
        threats = data.get("security_assessment", {}).get("threat_matrix", [])
        recs = data.get("security_assessment", {}).get("summary_recommendations", [])
        compliance = data.get("security_assessment", {}).get("compliance_status", {})

        badge_color = "#10b981" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")

        threat_rows = ""
        for t in threats:
            sev_color = "#ef4444" if t["severity"] in ("CRITICAL", "HIGH") else "#f59e0b"
            threat_rows += f"""
            <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 10px; font-weight: bold; color: {sev_color};">[{t['severity']}]</td>
                <td style="padding: 10px; font-weight: 600;">{t['title']}</td>
                <td style="padding: 10px;">{t['cvss']}</td>
                <td style="padding: 10px; color: #475569;">{t['impact']}</td>
            </tr>
            """

        if not threat_rows:
            threat_rows = """<tr><td colspan="4" style="padding: 15px; text-align: center; color: #10b981; font-weight: bold;">No critical or high security vulnerabilities identified.</td></tr>"""

        rec_items = "".join(f"<li style='margin-bottom: 8px;'>{r}</li>" for r in recs)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Executive IPsec Security Assessment Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #1e293b; padding: 40px; margin: 0; }}
        .card {{ background: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 30px; margin-bottom: 24px; border: 1px solid #e2e8f0; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #f1f5f9; padding-bottom: 20px; }}
        .title {{ font-size: 24px; font-weight: 800; color: #0f172a; margin: 0; }}
        .score-circle {{ width: 100px; height: 100px; border-radius: 50%; background: {badge_color}; color: white; display: flex; flex-direction: column; align-items: center; justify-content: center; font-weight: bold; }}
        .score-val {{ font-size: 32px; line-height: 1; }}
        .score-lbl {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
        .metric-box {{ background: #f1f5f9; border-radius: 8px; padding: 16px; }}
        .metric-label {{ font-size: 12px; text-transform: uppercase; color: #64748b; font-weight: bold; }}
        .metric-value {{ font-size: 18px; font-weight: 700; color: #0f172a; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }}
        th {{ background: #f8fafc; padding: 10px; text-align: left; font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div>
                <h1 class="title">Executive Security Assessment: IPsec VPN</h1>
                <p style="color: #64748b; margin: 6px 0 0 0;">National Technical Research Organisation (NTRO) • Automated Protocol Auditor</p>
                <p style="color: #94a3b8; font-size: 12px; margin: 4px 0 0 0;">Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
            <div class="score-circle">
                <div class="score-val">{score}</div>
                <div class="score-lbl">{risk}</div>
            </div>
        </div>

        <div class="grid">
            <div class="metric-box">
                <div class="metric-label">Operating Mode</div>
                <div class="metric-value">{mode} Mode</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">IKE Protocol</div>
                <div class="metric-value">{ike_ver}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">AI Traffic Fingerprint</div>
                <div class="metric-value">{ai_pred} ({ai_conf:.1%})</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Cryptographic Suite</div>
                <div class="metric-value" style="font-size: 14px;">{ciphers}</div>
            </div>
        </div>

        <h3 style="margin-top: 24px; color: #0f172a;">Regulatory & Cryptographic Compliance Status</h3>
        <div style="display: flex; gap: 16px; margin-bottom: 20px;">
            <div style="padding: 10px 18px; border-radius: 8px; background: {'#dcfce7' if compliance.get('NIST_SP_800_77_Rev1') else '#fee2e2'}; color: {'#166534' if compliance.get('NIST_SP_800_77_Rev1') else '#991b1b'}; font-weight: bold;">
                NIST SP 800-77: {'COMPLIANT' if compliance.get('NIST_SP_800_77_Rev1') else 'NON-COMPLIANT'}
            </div>
            <div style="padding: 10px 18px; border-radius: 8px; background: {'#dcfce7' if compliance.get('RFC_8221_ESP') else '#fee2e2'}; color: {'#166534' if compliance.get('RFC_8221_ESP') else '#991b1b'}; font-weight: bold;">
                RFC 8221 (ESP): {'COMPLIANT' if compliance.get('RFC_8221_ESP') else 'NON-COMPLIANT'}
            </div>
            <div style="padding: 10px 18px; border-radius: 8px; background: {'#dcfce7' if compliance.get('CNSA_Suite') else '#f1f5f9'}; color: {'#166534' if compliance.get('CNSA_Suite') else '#64748b'}; font-weight: bold;">
                NSA CNSA Suite: {'COMPLIANT' if compliance.get('CNSA_Suite') else 'OPTIONAL / NOT MET'}
            </div>
        </div>

        <h3 style="margin-top: 24px; color: #0f172a;">High-Priority Threat Findings</h3>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">Severity</th>
                    <th style="width: 35%;">Vulnerability Title</th>
                    <th style="width: 10%;">CVSS</th>
                    <th style="width: 40%;">Operational Impact</th>
                </tr>
            </thead>
            <tbody>
                {threat_rows}
            </tbody>
        </table>

        <h3 style="margin-top: 28px; color: #0f172a;">Executive Remediation Directives</h3>
        <ul style="background: #f8fafc; border-left: 4px solid #3b82f6; padding: 16px 20px 16px 36px; border-radius: 0 8px 8px 0; color: #334155; font-size: 14px;">
            {rec_items}
        </ul>
    </div>
</body>
</html>"""

    def build_technical_html(self, data: Dict[str, Any]) -> str:
        score = data.get("security_assessment", {}).get("overall_score", 0)
        risk = data.get("security_assessment", {}).get("risk_level", "UNKNOWN")
        threats = data.get("security_assessment", {}).get("threat_matrix", [])
        cats = data.get("security_assessment", {}).get("category_scores", {})
        flow = data.get("flow_features", {})
        esp = data.get("esp_summary", {})
        ike = data.get("ike_negotiation", {})
        ai = data.get("ai_classification", {})

        threat_details_html = ""
        for t in threats:
            threat_details_html += f"""
            <div style="background: #f8fafc; border-left: 4px solid #ef4444; border-radius: 4px; padding: 16px; margin-bottom: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h4 style="margin: 0; color: #0f172a;">{t['threat_id']}: {t['title']}</h4>
                    <span style="background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{t['severity']} (CVSS {t['cvss']})</span>
                </div>
                <p style="margin: 8px 0; color: #475569; font-size: 14px;"><strong>Component:</strong> {t['affected_component']}</p>
                <p style="margin: 8px 0; color: #334155; font-size: 14px;"><strong>Description:</strong> {t['description']}</p>
                <p style="margin: 8px 0; color: #334155; font-size: 14px;"><strong>Threat Impact:</strong> {t['impact']}</p>
                <div style="background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; margin-top: 8px;">
                    # Remediation Directive:<br>{t['remediation']}
                </div>
            </div>
            """

        if not threat_details_html:
            threat_details_html = "<p style='color: #10b981; font-weight: bold;'>Zero security violations detected. IPsec configuration conforms to rigorous baseline standards.</p>"

        # AI Probability Bars
        ai_bars = ""
        for cls_name, prob in ai.get("probabilities", {}).items():
            pct = int(prob * 100)
            ai_bars += f"""
            <div style="margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; font-size: 12px; font-weight: 600; color: #475569;">
                    <span>{cls_name}</span>
                    <span>{pct}%</span>
                </div>
                <div style="background: #e2e8f0; height: 6px; border-radius: 3px; overflow: hidden; margin-top: 2px;">
                    <div style="background: #3b82f6; width: {pct}%; height: 100%;"></div>
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Deep Technical IPsec Security Assessment Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; margin: 0; }}
        .card {{ background: #1e293b; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); padding: 30px; margin-bottom: 24px; border: 1px solid #334155; }}
        .title {{ font-size: 26px; font-weight: 800; color: #f8fafc; margin: 0; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }}
        .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 20px 0; }}
        .stat-box {{ background: #0f172a; border-radius: 8px; padding: 16px; border: 1px solid #334155; }}
        .stat-label {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 700; }}
        .stat-val {{ font-size: 20px; font-weight: 700; color: #f8fafc; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
        th {{ background: #0f172a; padding: 10px; text-align: left; font-weight: 600; color: #94a3b8; border-bottom: 2px solid #334155; }}
        td {{ padding: 10px; border-bottom: 1px solid #334155; color: #cbd5e1; }}
    </style>
</head>
<body>
    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 20px;">
            <div>
                <h1 class="title">Technical Protocol Audit & Cryptographic Telemetry</h1>
                <p style="color: #94a3b8; margin: 6px 0 0 0;">Comprehensive Analysis of Captured IPsec Network Traces (NTRO)</p>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 32px; font-weight: 900; color: #38bdf8;">{score}/100</div>
                <div style="font-size: 12px; font-weight: bold; color: #94a3b8;">RISK: {risk}</div>
            </div>
        </div>

        <h3 style="color: #38bdf8; margin-top: 24px;">1. Security Association & Protocol Dissection</h3>
        <div class="grid-3">
            <div class="stat-box">
                <div class="stat-label">IKE Version & Mode</div>
                <div class="stat-val">{ike.get('ike_version', 'Unknown')} ({esp.get('inferred_mode', 'Tunnel')} Mode)</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Active SPI Identifiers</div>
                <div class="stat-val" style="font-size: 14px; word-break: break-all;">{', '.join(esp.get('spis', [])) or 'N/A'}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Shannon Payload Entropy</div>
                <div class="stat-val">{esp.get('average_entropy', 0.0)} bits/byte</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Negotiated Component</th>
                    <th>Extracted Transform / Attribute</th>
                    <th>Cryptographic Standard</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Encryption Ciphers</td><td>{', '.join(ike.get('encryption_algorithms', ['None']))}</td><td>NIST SP 800-77 / RFC 8221</td></tr>
                <tr><td>Integrity Hashes</td><td>{', '.join(ike.get('integrity_algorithms', ['None']))}</td><td>HMAC FIPS-198-1</td></tr>
                <tr><td>Diffie-Hellman Groups</td><td>{', '.join(ike.get('dh_groups', ['None']))}</td><td>RFC 8247</td></tr>
                <tr><td>Perfect Forward Secrecy</td><td>{'ENFORCED (YES)' if ike.get('has_pfs') else 'DISABLED (NO)'}</td><td>Child SA Key Isolation</td></tr>
                <tr><td>Anti-Replay Window Status</td><td>{'0 Errors / Clean' if esp.get('replay_errors', 0) == 0 else f"{esp.get('replay_errors')} Sequence Duplicates Detected!"}</td><td>RFC 4303 Section 3.4.3</td></tr>
            </tbody>
        </table>

        <h3 style="color: #38bdf8; margin-top: 30px;">2. AI Encrypted Traffic Payload Fingerprinting</h3>
        <div class="grid-2">
            <div class="stat-box">
                <div class="stat-label">Predicted ESP Traffic Payload</div>
                <div class="stat-val" style="color: #38bdf8; font-size: 24px;">{ai.get('predicted_class', 'Unknown')}</div>
                <p style="font-size: 13px; color: #94a3b8; margin: 8px 0 0 0;">AI Confidence Score: <strong>{ai.get('confidence_score', 0.0):.1%}</strong> ({ai.get('model_version', 'ML')})</p>
                <div style="margin-top: 16px;">
                    {ai_bars}
                </div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Statistical Flow Dynamics</div>
                <table>
                    <tr><td>Total Captured Packets</td><td>{flow.get('pkt_count', 0)} pkts</td></tr>
                    <tr><td>Total Transferred Volume</td><td>{flow.get('byte_count', 0)} bytes</td></tr>
                    <tr><td>Mean Packet Length</td><td>{flow.get('len_mean', 0.0)} bytes (±{flow.get('len_std', 0.0)})</td></tr>
                    <tr><td>Inter-Arrival Time (Mean)</td><td>{flow.get('iat_mean', 0.0)*1000:.2f} ms</td></tr>
                    <tr><td>Mean Jitter</td><td>{flow.get('jitter', 0.0)*1000:.2f} ms</td></tr>
                    <tr><td>Average Burst Size</td><td>{flow.get('avg_burst_size', 1.0)} pkts/burst</td></tr>
                </table>
            </div>
        </div>

        <h3 style="color: #38bdf8; margin-top: 30px;">3. Detailed Threat Matrix & Hardening Guidance</h3>
        {threat_details_html}
    </div>
</body>
</html>"""
