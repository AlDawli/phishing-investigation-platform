"""
Attachment analysis: hashing (already done at parse time), risky-extension
detection, and YARA rule matching against raw attachment bytes.
"""
import os
from typing import Any, Dict, List

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".ps1",
    ".hta", ".wsf", ".lnk", ".iso", ".img", ".docm", ".xlsm", ".pptm",
}

DEFAULT_YARA_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "yara_rules", "phishing_rules.yar")


def _compile_rules(rules_path: str):
    if not HAVE_YARA or not os.path.exists(rules_path):
        return None
    try:
        return yara.compile(filepath=rules_path)
    except Exception:
        return None


def analyze(attachments: List[Dict[str, Any]], rules_path: str = DEFAULT_YARA_RULES_PATH) -> Dict[str, Any]:
    compiled_rules = _compile_rules(rules_path)
    findings: List[str] = []
    results = []

    for att in attachments:
        filename = att.get("filename", "unnamed")
        ext = os.path.splitext(filename)[1].lower()
        risky_ext = ext in RISKY_EXTENSIONS

        yara_matches = []
        if compiled_rules and att.get("_bytes"):
            try:
                matches = compiled_rules.match(data=att["_bytes"])
                yara_matches = [m.rule for m in matches]
            except Exception:
                yara_matches = []

        if risky_ext:
            findings.append(f"Attachment '{filename}' has a high-risk extension ({ext})")
        if yara_matches:
            findings.append(f"Attachment '{filename}' matched YARA rule(s): {', '.join(yara_matches)}")

        results.append(
            {
                "filename": filename,
                "content_type": att.get("content_type"),
                "size_bytes": att.get("size_bytes"),
                "md5": att.get("md5"),
                "sha1": att.get("sha1"),
                "sha256": att.get("sha256"),
                "risky_extension": risky_ext,
                "yara_matches": yara_matches,
            }
        )

    return {
        "attachments": results,
        "attachment_count": len(results),
        "any_risky": any(r["risky_extension"] or r["yara_matches"] for r in results),
        "findings": findings,
        "yara_engine_available": HAVE_YARA,
    }
