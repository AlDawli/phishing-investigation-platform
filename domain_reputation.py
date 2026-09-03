"""
Domain reputation: WHOIS-based domain-age check (newly-registered domains
are one of the strongest phishing signals), plus lightweight lexical
heuristics (excessive hyphens/digits, suspicious TLDs).
"""
import datetime
from typing import Any, Dict, List

try:
    import whois
    HAVE_WHOIS = True
except ImportError:
    HAVE_WHOIS = False

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
    ".click", ".link", ".zip", ".mov", ".icu",
}


def _domain_age_days(domain: str, timeout: int) -> int:
    if not HAVE_WHOIS:
        return -1
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return -1
        if isinstance(created, datetime.datetime):
            created = created.replace(tzinfo=None)
            return (datetime.datetime.utcnow() - created).days
        return -1
    except Exception:
        return -1


def _lexical_flags(domain: str) -> List[str]:
    flags = []
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flags.append(f"Domain uses a commonly-abused TLD ({domain.split('.')[-1]})")
    if domain.count("-") >= 3:
        flags.append("Domain contains an unusually high number of hyphens")
    digits = sum(c.isdigit() for c in domain)
    if digits >= 4:
        flags.append("Domain contains an unusually high number of digits")
    return flags


def check_domain(domain: str, config: dict) -> Dict[str, Any]:
    live_lookups = config.get("network", {}).get("enable_live_lookups", True)
    timeout = config.get("network", {}).get("request_timeout", 10)
    newly_registered_threshold = config.get("scoring", {}).get("newly_registered_days", 30)

    age_days = _domain_age_days(domain, timeout) if live_lookups else -1
    is_newly_registered = 0 <= age_days < newly_registered_threshold

    findings = _lexical_flags(domain)
    if is_newly_registered:
        findings.append(f"Domain '{domain}' was registered {age_days} day(s) ago (< {newly_registered_threshold}-day threshold)")
    elif age_days == -1:
        findings.append(f"WHOIS creation date unavailable for '{domain}' (unable to confirm domain age)")

    return {
        "domain": domain,
        "age_days": age_days,
        "is_newly_registered": is_newly_registered,
        "findings": findings,
    }


def check_domains(domains: List[str], config: dict) -> Dict[str, Any]:
    results = {d: check_domain(d, config) for d in domains}
    any_newly_registered = any(r["is_newly_registered"] for r in results.values())
    all_findings = [f for r in results.values() for f in r["findings"]]
    return {
        "results": results,
        "any_newly_registered": any_newly_registered,
        "findings": all_findings,
    }
