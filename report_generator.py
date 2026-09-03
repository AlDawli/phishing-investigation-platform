"""
Assembles the final investigation report in both machine-readable (JSON,
for SIEM/SOAR ingestion) and human-readable (HTML) formats.
"""
import datetime
import json
import os
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


def build_report(
    parsed_email: Dict[str, Any],
    header_result: Dict[str, Any],
    auth_result: Dict[str, Any],
    domain_result: Dict[str, Any],
    url_result: Dict[str, Any],
    ip_result: Dict[str, Any],
    attachment_result: Dict[str, Any],
    mitre_result: list,
    risk_result: Dict[str, Any],
    vt_url_scores: Dict[str, str],
    vt_hash_scores: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "email": {
            "subject": parsed_email.get("subject"),
            "from": parsed_email.get("from"),
            "date": parsed_email.get("date"),
            "message_id": parsed_email.get("message_id"),
        },
        "risk": risk_result,
        "sender_analysis": header_result,
        "authentication": auth_result,
        "url_analysis": url_result,
        "domain_reputation": domain_result,
        "ip_reputation": ip_result,
        "attachment_analysis": attachment_result,
        "mitre_attack_mapping": mitre_result,
        "virustotal": {"url_scores": vt_url_scores, "hash_scores": vt_hash_scores},
    }


def write_json(report: Dict[str, Any], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)


def write_html(report: Dict[str, Any], parsed_email: Dict[str, Any], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")

    html = template.render(
        subject=parsed_email.get("subject", "(no subject)"),
        from_addr=parsed_email.get("from", {}).get("address", ""),
        from_display=parsed_email.get("from", {}).get("display_name", ""),
        x_mailer=parsed_email.get("x_mailer", ""),
        generated_at=report["generated_at"],
        risk_score=report["risk"]["risk_score"],
        severity=report["risk"]["severity"],
        indicators=report["risk"]["indicators"],
        header=report["sender_analysis"],
        auth=report["authentication"],
        url=report["url_analysis"],
        domain=report["domain_reputation"],
        attachment=report["attachment_analysis"],
        mitre=report["mitre_attack_mapping"],
        vt_url_scores=report["virustotal"]["url_scores"],
        vt_hash_scores=report["virustotal"]["hash_scores"],
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
