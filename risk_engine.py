"""
Aggregates every module's findings into a single weighted risk score (0-100)
and a severity band, plus a short human-readable indicator list -- the
summary block analysts see first in the report.
"""
from typing import Any, Dict, List

# Weight table: tuned so that a "textbook" phishing email (spoofed sender +
# newly registered domain + malicious URL + malicious attachment) lands
# around 85-90, matching the target HIGH severity example.
WEIGHTS = {
    "suspicious_sender": 20,
    "auth_failed": 12,
    "newly_registered_domain": 20,
    "malicious_url": 25,
    "url_display_mismatch": 8,
    "malicious_attachment": 25,
    "risky_attachment_extension": 10,
    "malicious_ip": 10,
    "header_anomaly": 5,
}


def _severity_for(score: int, thresholds: Dict[str, int]) -> str:
    if score >= thresholds.get("HIGH", 70):
        return "HIGH"
    if score >= thresholds.get("MEDIUM", 40):
        return "MEDIUM"
    return "LOW"


def compute_risk(
    header_result: Dict[str, Any],
    auth_result: Dict[str, Any],
    domain_result: Dict[str, Any],
    url_result: Dict[str, Any],
    ip_result: Dict[str, Any],
    attachment_result: Dict[str, Any],
    vt_url_hits: List[Dict[str, Any]],
    vt_attachment_hits: List[Dict[str, Any]],
    config: dict,
) -> Dict[str, Any]:
    score = 0
    indicators: List[str] = []

    if header_result.get("suspicious_sender"):
        score += WEIGHTS["suspicious_sender"]
        indicators.append("Suspicious Sender")

    if auth_result.get("auth_failed"):
        score += WEIGHTS["auth_failed"]
        indicators.append("SPF/DKIM/DMARC Failure")

    if domain_result.get("any_newly_registered"):
        score += WEIGHTS["newly_registered_domain"]
        indicators.append("Newly Registered Domain")

    if vt_url_hits:
        score += WEIGHTS["malicious_url"]
        indicators.append("Malicious URL")
    elif url_result.get("display_href_mismatches"):
        score += WEIGHTS["url_display_mismatch"]
        indicators.append("Suspicious Link (Display/Href Mismatch)")

    malicious_ips = [ip for ip, r in ip_result.get("results", {}).items() if r.get("malicious")]
    if malicious_ips:
        score += WEIGHTS["malicious_ip"]
        indicators.append("Malicious IP")

    if vt_attachment_hits or any(
        a.get("yara_matches") for a in attachment_result.get("attachments", [])
    ):
        score += WEIGHTS["malicious_attachment"]
        indicators.append("Attachment Hash")
    elif attachment_result.get("any_risky"):
        score += WEIGHTS["risky_attachment_extension"]
        indicators.append("Risky Attachment Extension")

    if header_result.get("received_hop_count", 0) == 0 or header_result.get("suspicious_mailer"):
        score += WEIGHTS["header_anomaly"]
        indicators.append("Header Anomaly")

    score = min(score, 100)
    thresholds = config.get("scoring", {}).get("thresholds", {"HIGH": 70, "MEDIUM": 40, "LOW": 0})
    severity = _severity_for(score, thresholds)

    return {
        "risk_score": score,
        "severity": severity,
        "indicators": indicators,
    }
