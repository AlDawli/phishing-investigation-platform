"""
Header + sender analysis: display-name spoofing, From/Reply-To/Return-Path
mismatches, Received chain hop count, suspicious mailer strings, and
lookalike-domain (typosquat) detection against a small brand watch-list.
"""
import re
from typing import Any, Dict, List

try:
    import Levenshtein
    HAVE_LEVENSHTEIN = True
except ImportError:
    HAVE_LEVENSHTEIN = False

import tldextract

# Use the bundled public-suffix-list snapshot only -- never attempt a live
# fetch of publicsuffix.org, so this works fully offline / in sandboxed
# environments and never adds a network dependency to a security tool.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# Small default watch-list; extend freely for your org's most-impersonated brands.
KNOWN_BRAND_DOMAINS = [
    "microsoft.com", "office365.com", "outlook.com", "google.com", "gmail.com",
    "apple.com", "paypal.com", "amazon.com", "docusign.com", "dropbox.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "linkedin.com",
]

FREE_MAIL_PROVIDERS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com", "icloud.com"}


def _registered_domain(addr: str) -> str:
    if "@" not in addr:
        return ""
    domain = addr.rsplit("@", 1)[-1].lower()
    ext = _TLD_EXTRACTOR(domain)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else domain


def _lookalike_score(domain: str) -> Dict[str, Any]:
    """Cheap typosquat check via edit distance to known brand domains."""
    if not domain or not HAVE_LEVENSHTEIN:
        return {"is_lookalike": False, "closest_brand": None, "distance": None}

    best_brand, best_dist = None, 99
    for brand in KNOWN_BRAND_DOMAINS:
        d = Levenshtein.distance(domain, brand)
        if d < best_dist:
            best_brand, best_dist = brand, d

    # Distance 1-2 on a domain that isn't the exact brand = classic typosquat range.
    is_lookalike = 0 < best_dist <= 2 and domain != best_brand
    return {"is_lookalike": is_lookalike, "closest_brand": best_brand, "distance": best_dist}


def analyze(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    from_addr = parsed_email["from"]["address"]
    from_display = parsed_email["from"]["display_name"]
    reply_to_addr = parsed_email["reply_to"]["address"]
    return_path = parsed_email["return_path"]

    from_domain = _registered_domain(from_addr)
    reply_to_domain = _registered_domain(reply_to_addr) if reply_to_addr else ""
    return_path_domain = _registered_domain(return_path) if return_path else ""

    findings: List[str] = []

    reply_to_mismatch = bool(reply_to_addr) and reply_to_domain != from_domain
    if reply_to_mismatch:
        findings.append(f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})")

    return_path_mismatch = bool(return_path) and return_path_domain != from_domain
    if return_path_mismatch:
        findings.append(f"Return-Path domain ({return_path_domain}) differs from From domain ({from_domain})")

    # Display name impersonation: display name looks like a brand but the
    # actual sending domain doesn't match (e.g. "Microsoft Support" <foo@evil.tk>)
    display_name_spoof = False
    display_lower = from_display.lower()
    for brand in KNOWN_BRAND_DOMAINS:
        brand_name = brand.split(".")[0]
        if brand_name in display_lower and brand not in from_domain:
            display_name_spoof = True
            findings.append(
                f"Display name references '{brand_name}' but sender domain is '{from_domain}'"
            )
            break

    lookalike = _lookalike_score(from_domain)
    if lookalike["is_lookalike"]:
        findings.append(
            f"Sender domain '{from_domain}' is a likely lookalike of '{lookalike['closest_brand']}' "
            f"(edit distance {lookalike['distance']})"
        )

    free_mail_business_pretext = (
        from_domain in FREE_MAIL_PROVIDERS
        and any(k in display_lower for k in ["support", "billing", "security", "helpdesk", "admin", "it dept"])
    )
    if free_mail_business_pretext:
        findings.append("Free webmail domain used with an official-sounding display name")

    hop_count = len(parsed_email.get("received_chain", []))

    suspicious_mailer = False
    mailer = (parsed_email.get("x_mailer") or "").lower()
    if any(tok in mailer for tok in ["python", "curl", "phpmailer", "mailer-daemon", "sendblaster"]):
        suspicious_mailer = True
        findings.append(f"Sending client string looks automated/bulk: '{parsed_email.get('x_mailer')}'")

    suspicious_sender = any(
        [reply_to_mismatch, return_path_mismatch, display_name_spoof,
         lookalike["is_lookalike"], free_mail_business_pretext]
    )

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "display_name_spoof": display_name_spoof,
        "lookalike_domain": lookalike,
        "free_mail_business_pretext": free_mail_business_pretext,
        "received_hop_count": hop_count,
        "suspicious_mailer": suspicious_mailer,
        "suspicious_sender": suspicious_sender,
        "findings": findings,
    }
