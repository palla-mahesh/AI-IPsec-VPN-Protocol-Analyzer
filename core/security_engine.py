"""
Security Assessment & Threat Evaluation Engine
Evaluates IPsec VPN configurations against NIST SP 800-77 Rev. 1, RFC 8221,
RFC 8247, and CNSA standards. Generates composite risk scores, threat matrix,
and compliance findings.
"""

from typing import List, Dict, Any, Optional
import json
import os


class ThreatItem:
    def __init__(
        self,
        threat_id: str,
        title: str,
        category: str,
        severity: str,
        cvss: float,
        description: str,
        impact: str,
        remediation: str,
        affected_component: str
    ):
        self.threat_id = threat_id
        self.title = title
        self.category = category
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.cvss = cvss
        self.description = description
        self.impact = impact
        self.remediation = remediation
        self.affected_component = affected_component

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "cvss": self.cvss,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "affected_component": self.affected_component
        }


class SecurityAssessmentResult:
    def __init__(self):
        self.overall_score: int = 100  # 0 to 100
        self.risk_level: str = "SECURE"  # SECURE, LOW, MEDIUM, HIGH, CRITICAL
        self.compliance_status: Dict[str, bool] = {
            "NIST_SP_800_77_Rev1": True,
            "RFC_8221_ESP": True,
            "RFC_8247_IKEv2": True,
            "CNSA_Suite": False
        }
        self.threat_matrix: List[ThreatItem] = []
        self.category_scores: Dict[str, int] = {
            "cryptographic_strength": 100,
            "key_exchange_dh": 100,
            "forward_secrecy_pfs": 100,
            "replay_protection": 100,
            "protocol_hardening": 100
        }
        self.summary_recommendations: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "compliance_status": self.compliance_status,
            "threat_matrix": [t.to_dict() for t in self.threat_matrix],
            "category_scores": self.category_scores,
            "summary_recommendations": self.summary_recommendations,
            "total_vulnerabilities": len(self.threat_matrix),
            "critical_count": sum(1 for t in self.threat_matrix if t.severity == "CRITICAL"),
            "high_count": sum(1 for t in self.threat_matrix if t.severity == "HIGH"),
            "medium_count": sum(1 for t in self.threat_matrix if t.severity == "MEDIUM"),
            "low_count": sum(1 for t in self.threat_matrix if t.severity == "LOW")
        }


class SecurityEngine:
    """Automated security compliance and threat analysis for IPsec."""

    def __init__(self, rules_path: Optional[str] = None):
        if not rules_path:
            rules_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "config", "security_rules.json"
            )
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def _load_rules(self) -> Dict[str, Any]:
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def assess(
        self,
        ike_summary: Any,
        esp_summary: Any,
        flow_features: Any
    ) -> SecurityAssessmentResult:
        result = SecurityAssessmentResult()
        
        crypto_score = 100
        dh_score = 100
        pfs_score = 100
        replay_score = 100
        protocol_score = 100

        # Extract parameters
        ike_ver = getattr(ike_summary, "ike_version", "Unknown")
        is_ikev2 = getattr(ike_summary, "is_ikev2", False)
        is_aggressive = getattr(ike_summary, "is_aggressive_mode", False)
        ciphers = getattr(ike_summary, "encryption_algorithms", [])
        integrities = getattr(ike_summary, "integrity_algorithms", [])
        dh_groups = getattr(ike_summary, "dh_groups", [])
        has_pfs = getattr(ike_summary, "has_pfs", False)
        lifetimes = getattr(ike_summary, "key_lifetimes", [])
        
        replay_errors = getattr(esp_summary, "replay_errors", 0)
        seq_gaps = getattr(esp_summary, "sequence_gaps", 0)
        max_seq = getattr(esp_summary, "max_seq", 0)
        entropy = getattr(esp_summary, "average_entropy", 0.0)

        # 1. Cryptographic Cipher Evaluation
        has_approved_cipher = False
        has_cnsa_cipher = False
        for c in ciphers:
            c_upper = c.upper()
            if "3DES" in c_upper or "DES" in c_upper:
                crypto_score -= 45
                result.compliance_status["NIST_SP_800_77_Rev1"] = False
                result.compliance_status["RFC_8221_ESP"] = False
                result.threat_matrix.append(ThreatItem(
                    threat_id="SEC-CIPHER-001",
                    title="Sweet32 Vulnerability: Deprecated 64-bit Block Cipher (3DES/DES)",
                    category="Cryptographic Strength",
                    severity="HIGH",
                    cvss=7.5,
                    description=f"Identified cipher {c} uses a 64-bit block size vulnerable to collision/birthday attacks.",
                    impact="Adversary capturing traffic can retroactively recover plaintexts across long-running sessions.",
                    remediation="Upgrade IPsec SA proposals to AES-256-GCM or AES-128-GCM.",
                    affected_component=f"ESP/IKE Transform: {c}"
                ))
            elif "BLOWFISH" in c_upper:
                crypto_score -= 35
                result.compliance_status["NIST_SP_800_77_Rev1"] = False
                result.threat_matrix.append(ThreatItem(
                    threat_id="SEC-CIPHER-002",
                    title="Insecure Legacy Cipher: Blowfish",
                    category="Cryptographic Strength",
                    severity="MEDIUM",
                    cvss=5.9,
                    description="Blowfish has a 64-bit block size and is deprecated across modern IPsec standards.",
                    impact="Vulnerable to plaintext recovery on high volume flows.",
                    remediation="Configure AES-GCM (128-bit or 256-bit).",
                    affected_component=f"Transform: {c}"
                ))
            elif "AES-256-GCM" in c_upper:
                has_approved_cipher = True
                has_cnsa_cipher = True
            elif "AES-128-GCM" in c_upper or "AES" in c_upper:
                has_approved_cipher = True

        # Check Integrity Transforms
        for h in integrities:
            h_upper = h.upper()
            if "MD5" in h_upper:
                crypto_score -= 40
                result.compliance_status["NIST_SP_800_77_Rev1"] = False
                result.threat_matrix.append(ThreatItem(
                    threat_id="SEC-HASH-001",
                    title="Broken Integrity Algorithm: HMAC-MD5",
                    category="Cryptographic Strength",
                    severity="CRITICAL",
                    cvss=8.5,
                    description="MD5 is cryptographically broken and vulnerable to practical collision generation.",
                    impact="Data integrity of the IPsec tunnel cannot be assured; packets can be forged.",
                    remediation="Enforce HMAC-SHA256, HMAC-SHA384, or use AEAD ciphers (AES-GCM).",
                    affected_component=f"Integrity Transform: {h}"
                ))
            elif "SHA1" in h_upper:
                crypto_score -= 25
                result.compliance_status["NIST_SP_800_77_Rev1"] = False
                result.threat_matrix.append(ThreatItem(
                    threat_id="SEC-HASH-002",
                    title="Weak Hash Algorithm: HMAC-SHA1",
                    category="Cryptographic Strength",
                    severity="MEDIUM",
                    cvss=5.3,
                    description="SHA-1 is deprecated by NIST SP 800-131A due to collision vulnerability.",
                    impact="Weakens authentication against nation-state collision generation capabilities.",
                    remediation="Migrate to HMAC-SHA256 or HMAC-SHA512.",
                    affected_component=f"Integrity Transform: {h}"
                ))

        # Check Entropy (Detect Null Cipher or unencrypted payload)
        if esp_summary.packet_count > 5 and entropy < 7.0 and entropy > 0.1:
            crypto_score -= 50
            result.threat_matrix.append(ThreatItem(
                threat_id="SEC-ENTROPY-001",
                title="Suspicious Low-Entropy Payload (Possible ESP Null Encryption)",
                category="Cryptographic Strength",
                severity="CRITICAL",
                cvss=9.0,
                description=f"Average ESP payload entropy measured {round(entropy, 2)} bits/byte (expected > 7.9).",
                impact="Tunnel may be running NULL encryption (RFC 2410) exposing plaintext payloads.",
                remediation="Verify that ESP encryption transform is not set to NULL or ESP_NULL.",
                affected_component="ESP Encrypted Data"
            ))

        # 2. Diffie-Hellman Group Evaluation
        has_approved_dh = False
        for dh in dh_groups:
            dh_str = str(dh)
            if "Group 1 " in dh_str or "768-bit" in dh_str:
                dh_score -= 50
                result.compliance_status["NIST_SP_800_77_Rev1"] = False
                result.threat_matrix.append(ThreatItem(
                    threat_id="SEC-DH-001",
                    title="Broken Diffie-Hellman Group: Group 1 (768-bit MODP)",
                    category="Key Exchange",
                    severity="CRITICAL",
                    cvss=8.8,
                    description="768-bit MODP keys can be factored with modest academic computing resources.",
                    impact="Adversaries can precompute discrete logs, break session keys, and decrypt communication.",
                    remediation="Upgrade DH group to Group 14 (2048-bit), Group 19 (256-bit ECP), or Group 20 (384-bit ECP).",
                    affected_component=f"DH Proposal: {dh}"
                ))
            elif "Group 2 " in dh_str or "1024-bit" in dh_str:
                dh_score -= 40
                result.compliance_status["NIST_SP_800_77_Rev1"] = False
                result.threat_matrix.append(ThreatItem(
                    threat_id="SEC-DH-002",
                    title="Logjam Vulnerability: Weak Diffie-Hellman Group 2 (1024-bit MODP)",
                    category="Key Exchange",
                    severity="HIGH",
                    cvss=7.5,
                    description="1024-bit MODP groups are vulnerable to precomputation attacks (CVE-2015-4000).",
                    impact="Session keys can be compromised by state-level adversaries.",
                    remediation="Enforce minimum DH Group 14 (2048-bit MODP) or Group 19/20 (ECP).",
                    affected_component=f"DH Proposal: {dh}"
                ))
            elif "Group 5 " in dh_str or "1536-bit" in dh_str:
                dh_score -= 20
                result.compliance_status["NIST_SP_800_77_Rev1"] = False
                result.threat_matrix.append(ThreatItem(
                    threat_id="SEC-DH-003",
                    title="Legacy Diffie-Hellman Group 5 (1536-bit MODP)",
                    category="Key Exchange",
                    severity="MEDIUM",
                    cvss=5.3,
                    description="1536-bit MODP is below NIST 112-bit security requirement (requires min 2048-bit).",
                    impact="Approaching end of cryptographic safety window.",
                    remediation="Upgrade to Group 14 or Group 19.",
                    affected_component=f"DH Proposal: {dh}"
                ))
            elif any(g in dh_str for g in ("Group 14", "Group 19", "Group 20", "Group 21", "Curve25519")):
                has_approved_dh = True

        # 3. Perfect Forward Secrecy (PFS)
        if not has_pfs:
            pfs_score -= 40
            result.compliance_status["NIST_SP_800_77_Rev1"] = False
            result.threat_matrix.append(ThreatItem(
                threat_id="SEC-PFS-001",
                title="Perfect Forward Secrecy (PFS) Not Enforced in Child SA",
                category="Forward Secrecy",
                severity="HIGH",
                cvss=7.1,
                description="Child SAs are established without an independent Diffie-Hellman exchange.",
                impact="If the primary IKE SA key is compromised, all child traffic can be retroactively decrypted.",
                remediation="Enable PFS in IPsec configuration (e.g. pfs=yes in StrongSwan or esp_group in Cisco ASA).",
                affected_component="Child SA Negotiation"
            ))

        # 4. Replay Protection & Sequence Wraparound
        if replay_errors > 0:
            replay_score -= 30
            result.threat_matrix.append(ThreatItem(
                threat_id="SEC-REPLAY-001",
                title="Duplicate ESP Sequence Numbers Observed (Replay Threat)",
                category="Replay Protection",
                severity="HIGH",
                cvss=7.0,
                description=f"Observed {replay_errors} duplicate sequence numbers within the ESP stream.",
                impact="Potential replay attack in progress or malfunctioning anti-replay window on peer.",
                remediation="Verify anti-replay window is active and check network for packet duplication.",
                affected_component=f"ESP Replay Window (SPI: {esp_summary.spis})"
            ))
        if max_seq > 4000000000:
            replay_score -= 25
            result.threat_matrix.append(ThreatItem(
                threat_id="SEC-ESN-001",
                title="High ESP Sequence Counter without Extended Sequence Numbers (ESN)",
                category="Replay Protection",
                severity="MEDIUM",
                cvss=5.5,
                description="Sequence counter is nearing 32-bit ceiling without ESN (RFC 4303).",
                impact="Risk of session termination or sequence wraparound replay exposure.",
                remediation="Configure Extended Sequence Numbers (ESN) or trigger timely rekeying.",
                affected_component="ESP Sequence Counter"
            ))

        # 5. Protocol Hardening & IKE Version
        if is_aggressive:
            protocol_score -= 45
            result.threat_matrix.append(ThreatItem(
                threat_id="SEC-IKE-001",
                title="IKEv1 Aggressive Mode with PSK Vulnerability",
                category="Protocol Hardening",
                severity="HIGH",
                cvss=8.1,
                description="IKEv1 Aggressive Mode exposes the Pre-Shared Key hash in cleartext packet exchanges.",
                impact="Attackers can capture the handshake and conduct offline dictionary/rainbow table attacks.",
                remediation="Upgrade to IKEv2 or use IKEv1 Main Mode with RSA/ECDSA certificates.",
                affected_component="IKEv1 Phase 1 Exchange"
            ))
        elif not is_ikev2 and "IKEv1" in ike_ver:
            protocol_score -= 20
            result.compliance_status["RFC_8247_IKEv2"] = False
            result.threat_matrix.append(ThreatItem(
                threat_id="SEC-IKE-002",
                title="Deprecated Protocol: IKEv1 in Production Use",
                category="Protocol Hardening",
                severity="LOW",
                cvss=3.7,
                description="IKEv1 (RFC 2409) is legacy and has been superseded by IKEv2 (RFC 7296).",
                impact="IKEv1 lacks built-in NAT-T efficiency, ECN support, and resilient denial-of-service cookies.",
                remediation="Migrate VPN gateways to IKEv2.",
                affected_component=f"Protocol: {ike_ver}"
            ))

        # SA Lifetimes
        for lt in lifetimes:
            dur = lt.get("duration", 0)
            ltype = lt.get("type", "seconds")
            if ltype == "seconds":
                if dur > 86400:
                    protocol_score -= 15
                    result.threat_matrix.append(ThreatItem(
                        threat_id="SEC-LIFE-001",
                        title=f"Excessive SA Lifetime ({dur} seconds > 24 hours)",
                        category="Key Management",
                        severity="LOW",
                        cvss=3.3,
                        description="SA key lifetime exceeds recommended 24-hour limit under NIST SP 800-77.",
                        impact="Extended key usage increases exposure window to cryptanalytic attacks.",
                        remediation="Configure SA rekey lifetime between 3,600 and 28,800 seconds (1-8 hours).",
                        affected_component="SA Lifetime Attribute"
                    ))

        # Check CNSA Suite Compliance
        if has_cnsa_cipher and any("Group 20" in s or "384-bit" in s for s in dh_groups):
            result.compliance_status["CNSA_Suite"] = True

        # Clamp Category Scores (min 0, max 100)
        result.category_scores["cryptographic_strength"] = max(0, min(100, crypto_score))
        result.category_scores["key_exchange_dh"] = max(0, min(100, dh_score))
        result.category_scores["forward_secrecy_pfs"] = max(0, min(100, pfs_score))
        result.category_scores["replay_protection"] = max(0, min(100, replay_score))
        result.category_scores["protocol_hardening"] = max(0, min(100, protocol_score))

        # Compute Composite Weighted Overall Score
        # Weights: Crypto 30%, DH 20%, PFS 20%, Replay 15%, Protocol 15%
        comp = (
            0.30 * result.category_scores["cryptographic_strength"] +
            0.20 * result.category_scores["key_exchange_dh"] +
            0.20 * result.category_scores["forward_secrecy_pfs"] +
            0.15 * result.category_scores["replay_protection"] +
            0.15 * result.category_scores["protocol_hardening"]
        )
        result.overall_score = int(round(max(0, min(100, comp))))

        # Determine Risk Level
        if result.overall_score >= 85:
            result.risk_level = "SECURE"
        elif result.overall_score >= 70:
            result.risk_level = "LOW RISK"
        elif result.overall_score >= 50:
            result.risk_level = "MEDIUM RISK"
        elif result.overall_score >= 30:
            result.risk_level = "HIGH RISK"
        else:
            result.risk_level = "CRITICAL RISK"

        # Actionable Recommendations
        if not result.compliance_status["NIST_SP_800_77_Rev1"]:
            result.summary_recommendations.append("Bring IPsec configuration into compliance with NIST SP 800-77 Rev. 1 by deprecating 3DES/MD5 and upgrading to AES-GCM.")
        if not has_pfs:
            result.summary_recommendations.append("Mandate Perfect Forward Secrecy (PFS) with DH Group 14 or higher for all Child SAs.")
        if is_aggressive:
            result.summary_recommendations.append("Immediately disable IKEv1 Aggressive Mode to prevent pre-shared key hash exposure.")
        if not result.summary_recommendations:
            result.summary_recommendations.append("IPsec configuration adheres to modern military and enterprise cryptographic standards.")

        # Deduplicate threat matrix items by threat_id
        deduped_threats = {}
        for t in result.threat_matrix:
            if t.threat_id not in deduped_threats:
                deduped_threats[t.threat_id] = t
            else:
                existing = deduped_threats[t.threat_id]
                if t.affected_component not in existing.affected_component:
                    existing.affected_component += f", {t.affected_component}"
        result.threat_matrix = list(deduped_threats.values())

        return result
