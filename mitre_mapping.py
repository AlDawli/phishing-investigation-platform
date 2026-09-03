"""
Maps derived indicators to MITRE ATT&CK (Enterprise) techniques. This is a
deterministic rule table, not an ML classifier -- transparent and easy to
extend as your detection logic grows.
"""
from typing import Any, Dict, List

TECHNIQUE_NAMES = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1204.002": "User Execution: Malicious File",
    "T1204.001": "User Execution: Malicious Link",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1036.007": "Masquerading: Double File Extension",
    "T1027.006": "Obfuscated Files or Information: HTML/Archive Smuggling",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1585.002": "Establish Accounts: Email Accounts",
    "T1078": "Valid Accounts",
    "T1656": "Impersonation",
}


def map_techniques(
    attachment_result: Dict[str, Any],
    url_result: Dict[str, Any],
    header_result: Dict[str, Any],
    domain_result: Dict[str, Any],
    auth_result: Dict[str, Any],
) -> List[Dict[str, str]]:
    hits = set()

    if attachment_result.get("attachment_count", 0) > 0:
        hits.add("T1566.001")
        if attachment_result.get("any_risky"):
            hits.add("T1204.002")
        for att in attachment_result.get("attachments", []):
            if "Obfuscated_PowerShell_Dropper" in att.get("yara_matches", []):
                hits.add("T1059.001")
            if "Suspicious_Double_Extension" in att.get("yara_matches", []):
                hits.add("T1036.007")
            if "Generic_Password_Protected_Zip_Lure" in att.get("yara_matches", []):
                hits.add("T1027.006")

    if url_result.get("url_count", 0) > 0:
        hits.add("T1566.002")
        hits.add("T1204.001")

    if header_result.get("display_name_spoof") or header_result.get("lookalike_domain", {}).get("is_lookalike"):
        hits.add("T1656")

    if header_result.get("free_mail_business_pretext"):
        hits.add("T1585.002")

    if domain_result.get("any_newly_registered"):
        hits.add("T1583.001")

    if auth_result.get("auth_failed"):
        hits.add("T1078")

    hits.add("T1566")  # parent technique always applies to a phishing case

    return [
        {"technique_id": tid, "technique_name": TECHNIQUE_NAMES.get(tid, "Unknown")}
        for tid in sorted(hits)
    ]
