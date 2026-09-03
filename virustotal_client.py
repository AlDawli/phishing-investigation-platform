"""
Thin wrapper around VirusTotal API v3 for IOC enrichment: file hashes,
domains, IPs, and URLs. Degrades gracefully (returns "checked: False") when
no API key is configured or the request fails, so the rest of the pipeline
never breaks on a missing key or rate limit.
"""
import base64
from typing import Any, Dict

import requests

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, config: dict):
        self.api_key = config.get("virustotal", {}).get("api_key", "")
        self.timeout = config.get("network", {}).get("request_timeout", 10)
        self.live = config.get("network", {}).get("enable_live_lookups", True)

    def _headers(self):
        return {"x-apikey": self.api_key}

    def _get(self, path: str) -> Dict[str, Any]:
        if not self.api_key or not self.live:
            return {"checked": False, "reason": "no API key configured or live lookups disabled"}
        try:
            resp = requests.get(f"{BASE_URL}{path}", headers=self._headers(), timeout=self.timeout)
            if resp.status_code == 404:
                return {"checked": True, "found": False}
            resp.raise_for_status()
            data = resp.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "checked": True,
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("attributes", {}).get("reputation"),
                "permalink": f"https://www.virustotal.com/gui/{path.split('/')[1]}/{path.split('/')[-1]}",
            }
        except Exception as exc:
            return {"checked": False, "reason": str(exc)}

    def check_hash(self, sha256: str) -> Dict[str, Any]:
        return self._get(f"/files/{sha256}")

    def check_domain(self, domain: str) -> Dict[str, Any]:
        return self._get(f"/domains/{domain}")

    def check_ip(self, ip: str) -> Dict[str, Any]:
        return self._get(f"/ip_addresses/{ip}")

    def check_url(self, url: str) -> Dict[str, Any]:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return self._get(f"/urls/{url_id}")

    @staticmethod
    def is_malicious(vt_result: Dict[str, Any], threshold: int = 2) -> bool:
        return vt_result.get("checked") and vt_result.get("found") and vt_result.get("malicious", 0) >= threshold
