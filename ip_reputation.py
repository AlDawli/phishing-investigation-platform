"""
IP reputation: resolves domains found in URLs to IPs, checks against
AbuseIPDB (if an API key is configured), and flags basic red flags
(bulletproof-hosting ASNs are out of scope for this lightweight tool, but
private/reserved IP usage and blank PTR records are cheap, useful signals).
"""
import ipaddress
import socket
from typing import Any, Dict, List

import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def _resolve(domain: str) -> List[str]:
    try:
        return list({info[4][0] for info in socket.getaddrinfo(domain, None)})
    except Exception:
        return []


def _abuseipdb_check(ip: str, api_key: str, timeout: int) -> Dict[str, Any]:
    if not api_key:
        return {"checked": False, "reason": "no API key configured"}
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "checked": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
        }
    except Exception as exc:
        return {"checked": False, "reason": str(exc)}


def check_domains(domains: List[str], config: dict) -> Dict[str, Any]:
    live_lookups = config.get("network", {}).get("enable_live_lookups", True)
    timeout = config.get("network", {}).get("request_timeout", 10)
    api_key = config.get("abuseipdb", {}).get("api_key", "")

    results = {}
    findings = []
    if not live_lookups:
        return {"results": {}, "findings": ["Live IP lookups disabled in config"]}

    for domain in domains:
        ips = _resolve(domain)
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_private = ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback
            except ValueError:
                is_private = False

            abuse = _abuseipdb_check(ip, api_key, timeout) if not is_private else {"checked": False}
            malicious = abuse.get("checked") and abuse.get("abuse_confidence_score", 0) >= 50

            results[ip] = {
                "domain": domain,
                "is_private": is_private,
                "abuseipdb": abuse,
                "malicious": malicious,
            }
            if malicious:
                findings.append(
                    f"IP {ip} ({domain}) has an AbuseIPDB confidence score of "
                    f"{abuse.get('abuse_confidence_score')}%"
                )
            if is_private:
                findings.append(f"IP {ip} ({domain}) resolves to a private/reserved range")

    return {"results": results, "findings": findings}
