"""
Lightweight smoke tests -- run with: python -m pytest tests/
Uses the bundled sample_phishing.eml fixture and runs fully offline
(live_lookups disabled) so it works in CI without API keys or network.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.eml_parser import ParsedEmail
from src import header_analysis, auth_analysis, url_extractor
from src import domain_reputation, attachment_analysis
from src import mitre_mapping, risk_engine

SAMPLE = os.path.join(os.path.dirname(__file__), "sample_phishing.eml")
OFFLINE_CONFIG = {
    "network": {"enable_live_lookups": False, "request_timeout": 5},
    "scoring": {"newly_registered_days": 30, "thresholds": {"HIGH": 70, "MEDIUM": 40, "LOW": 0}},
    "abuseipdb": {"api_key": ""},
    "virustotal": {"api_key": ""},
}


def _parse():
    parsed = ParsedEmail(SAMPLE)
    return parsed.data, parsed.to_dict()


def test_parser_extracts_core_fields():
    _, clean = _parse()
    assert clean["subject"].startswith("Urgent")
    assert clean["from"]["address"] == "alerts@micros0ft-secure.tk"
    assert len(clean["attachments"]) == 1
    assert clean["attachments"][0]["filename"] == "Account_Verification_Form.xlsm"


def test_header_analysis_flags_spoofing():
    _, clean = _parse()
    result = header_analysis.analyze(clean)
    assert result["suspicious_sender"] is True
    assert result["display_name_spoof"] is True
    assert result["reply_to_mismatch"] is True


def test_auth_analysis_detects_failures():
    _, clean = _parse()
    header_result = header_analysis.analyze(clean)
    result = auth_analysis.analyze(clean, header_result["from_domain"], OFFLINE_CONFIG)
    assert result["auth_failed"] is True
    assert result["spf"]["result"] == "fail"


def test_url_extractor_finds_mismatch():
    _, clean = _parse()
    result = url_extractor.extract(clean)
    assert result["url_count"] >= 2
    assert len(result["display_href_mismatches"]) >= 1


def test_attachment_analysis_flags_risky_extension():
    raw, _ = _parse()
    result = attachment_analysis.analyze(raw["attachments"])
    assert result["any_risky"] is True
    assert result["attachments"][0]["risky_extension"] is True


def test_risk_engine_produces_high_or_medium_severity():
    raw, clean = _parse()
    header_result = header_analysis.analyze(clean)
    auth_result = auth_analysis.analyze(clean, header_result["from_domain"], OFFLINE_CONFIG)
    url_result = url_extractor.extract(clean)
    domain_result = domain_reputation.check_domains([header_result["from_domain"]], OFFLINE_CONFIG)
    attachment_result = attachment_analysis.analyze(raw["attachments"])

    risk = risk_engine.compute_risk(
        header_result, auth_result, domain_result, url_result,
        {"results": {}}, attachment_result, [], [], OFFLINE_CONFIG,
    )
    assert risk["severity"] in ("MEDIUM", "HIGH")
    assert 0 <= risk["risk_score"] <= 100
    assert "Suspicious Sender" in risk["indicators"]


def test_mitre_mapping_includes_phishing_parent():
    raw, clean = _parse()
    header_result = header_analysis.analyze(clean)
    auth_result = auth_analysis.analyze(clean, header_result["from_domain"], OFFLINE_CONFIG)
    url_result = url_extractor.extract(clean)
    domain_result = domain_reputation.check_domains([header_result["from_domain"]], OFFLINE_CONFIG)
    attachment_result = attachment_analysis.analyze(raw["attachments"])

    techniques = mitre_mapping.map_techniques(
        attachment_result, url_result, header_result, domain_result, auth_result
    )
    ids = {t["technique_id"] for t in techniques}
    assert "T1566" in ids
    assert "T1566.001" in ids  # has attachment
    assert "T1566.002" in ids  # has URLs
