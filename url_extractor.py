"""
Extracts URLs from both the plaintext and HTML body of an email, and flags
"display-text vs actual-href" mismatches -- a classic phishing lure pattern
(e.g. text reads "https://paypal.com" but the href points to a credential
harvesting domain).
"""
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import tldextract

# Bundled snapshot only -- see header_analysis.py for rationale.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+)""",
)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}


def _clean(url: str) -> str:
    return url.rstrip(".,;:!?)'\"")


def _registered_domain(url: str) -> str:
    try:
        host = urlparse(url if "://" in url else f"http://{url}").netloc
        ext = _TLD_EXTRACTOR(host)
        return f"{ext.domain}.{ext.suffix}" if ext.suffix else host
    except Exception:
        return ""


def extract(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    urls_found = set()
    mismatches: List[Dict[str, str]] = []

    for raw in URL_REGEX.findall(parsed_email.get("body_text", "") or ""):
        urls_found.add(_clean(raw))

    html = parsed_email.get("body_html", "") or ""
    if html:
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            href = _clean(a["href"])
            display_text = a.get_text(strip=True)
            if href.lower().startswith(("http://", "https://", "www.")):
                urls_found.add(href)

            # Does the visible text itself look like a URL/domain that
            # differs from where the link actually goes?
            text_match = URL_REGEX.search(display_text)
            if text_match:
                display_url = _clean(text_match.group(1))
                if _registered_domain(display_url) and _registered_domain(display_url) != _registered_domain(href):
                    mismatches.append({"displayed_as": display_url, "actual_href": href})

    enriched = []
    shortener_hits = []
    for url in sorted(urls_found):
        domain = _registered_domain(url)
        is_shortener = domain in URL_SHORTENERS
        if is_shortener:
            shortener_hits.append(url)
        enriched.append({"url": url, "domain": domain, "is_shortener": is_shortener})

    findings = []
    if mismatches:
        findings.append(f"{len(mismatches)} link(s) where displayed text does not match the actual destination")
    if shortener_hits:
        findings.append(f"{len(shortener_hits)} URL shortener link(s) detected -- destination is obscured")

    return {
        "urls": enriched,
        "url_count": len(enriched),
        "display_href_mismatches": mismatches,
        "shortener_count": len(shortener_hits),
        "findings": findings,
    }
