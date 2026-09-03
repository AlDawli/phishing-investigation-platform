"""
SPF / DKIM / DMARC verification.

Primary source of truth: the Authentication-Results header stamped by the
receiving mail server (most reliable, since it reflects the actual SMTP
transaction). As a fallback / cross-check, this module can also perform a
live DNS lookup for SPF and DMARC TXT records when live lookups are enabled.
"""
import re
from typing import Any, Dict, Optional

try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False


def _extract_result(auth_results_headers: list, mechanism: str) -> Optional[str]:
    """Pulls e.g. spf=pass / dkim=fail / dmarc=none out of Authentication-Results."""
    combined = " ".join(auth_results_headers)
    match = re.search(rf"{mechanism}=(\w+)", combined, re.IGNORECASE)
    return match.group(1).lower() if match else None


def _dns_txt_lookup(name: str, timeout: int = 5) -> list:
    if not HAVE_DNS:
        return []
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
        return [b"".join(r.strings).decode(errors="replace") for r in answers]
    except Exception:
        return []


def analyze(parsed_email: Dict[str, Any], from_domain: str, config: dict) -> Dict[str, Any]:
    auth_headers = parsed_email.get("authentication_results", [])
    live_lookups = config.get("network", {}).get("enable_live_lookups", True)
    timeout = config.get("network", {}).get("request_timeout", 10)

    spf_result = _extract_result(auth_headers, "spf") or "none"
    dkim_result = _extract_result(auth_headers, "dkim") or ("pass" if parsed_email.get("dkim_signature") else "none")
    dmarc_result = _extract_result(auth_headers, "dmarc") or "none"

    spf_record, dmarc_record = None, None
    if live_lookups and from_domain:
        spf_candidates = _dns_txt_lookup(from_domain, timeout)
        spf_record = next((r for r in spf_candidates if r.startswith("v=spf1")), None)

        dmarc_candidates = _dns_txt_lookup(f"_dmarc.{from_domain}", timeout)
        dmarc_record = next((r for r in dmarc_candidates if r.startswith("v=DMARC1")), None)
        if dmarc_record and dmarc_result == "none":
            # Header didn't carry a verdict but a policy exists -- surface it as informational.
            pol_match = re.search(r"p=(\w+)", dmarc_record)
            dmarc_result = f"none (policy on record: p={pol_match.group(1)})" if pol_match else dmarc_result

    findings = []
    if spf_result not in ("pass",):
        findings.append(f"SPF check result: {spf_result.upper()}")
    if dkim_result not in ("pass",):
        findings.append(f"DKIM check result: {dkim_result.upper()}")
    if dmarc_result.split(" ")[0] not in ("pass",):
        findings.append(f"DMARC check result: {dmarc_result.upper()}")

    auth_failed = spf_result != "pass" or dkim_result != "pass" or dmarc_result.split(" ")[0] != "pass"

    return {
        "spf": {"result": spf_result, "record": spf_record},
        "dkim": {"result": dkim_result},
        "dmarc": {"result": dmarc_result, "record": dmarc_record},
        "auth_failed": auth_failed,
        "findings": findings,
    }
