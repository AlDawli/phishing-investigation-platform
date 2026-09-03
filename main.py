#!/usr/bin/env python3
"""
Phishing Investigation Platform - CLI entrypoint.

Usage:
    python main.py --input samples/phish.eml
    python main.py --input samples/phish.eml --config config/config.yaml --out reports/

Pipeline:
    Email -> Sender Analysis -> SPF/DKIM/DMARC -> Header Analysis ->
    URL Extraction -> Domain Reputation -> IP Reputation -> Attachment
    Hashing -> YARA -> VirusTotal -> MITRE ATT&CK Mapping -> Risk Scoring ->
    Report Generation
"""
import argparse
import os
import sys

from rich.console import Console
from rich.table import Table

sys.path.insert(0, os.path.dirname(__file__))

from src.config import load_config
from src.eml_parser import ParsedEmail
from src import header_analysis, auth_analysis, url_extractor
from src import domain_reputation, ip_reputation, attachment_analysis
from src.virustotal_client import VirusTotalClient
from src import mitre_mapping, risk_engine, report_generator

console = Console()


def run(input_path: str, config_path: str, out_dir: str) -> dict:
    config = load_config(config_path)

    console.rule(f"[bold]Phishing Investigation Platform")
    console.print(f"[dim]Input:[/dim] {input_path}")

    # 1. Parse the .eml
    parsed = ParsedEmail(input_path)
    email_data = parsed.data  # keeps _bytes for YARA scanning
    email_clean = parsed.to_dict()

    # 2. Sender / header analysis
    header_result = header_analysis.analyze(email_clean)

    # 3. SPF / DKIM / DMARC
    auth_result = auth_analysis.analyze(email_clean, header_result["from_domain"], config)

    # 4. URL extraction
    url_result = url_extractor.extract(email_clean)
    url_domains = sorted({u["domain"] for u in url_result["urls"] if u["domain"]})

    # 5. Domain reputation (sender domain + all URL domains)
    all_domains = sorted({header_result["from_domain"]} | set(url_domains))
    all_domains = [d for d in all_domains if d]
    domain_result = domain_reputation.check_domains(all_domains, config)

    # 6. IP reputation for URL domains
    ip_result = ip_reputation.check_domains(url_domains, config)

    # 7 + 8. Attachment hashing + YARA
    attachment_result = attachment_analysis.analyze(email_data["attachments"])

    # 9. VirusTotal enrichment
    vt = VirusTotalClient(config)
    vt_url_scores, vt_url_hits = {}, []
    for u in url_result["urls"]:
        res = vt.check_url(u["url"])
        if res.get("checked") and res.get("found"):
            vt_url_scores[u["url"]] = f"{res.get('malicious', 0)} engines"
            if VirusTotalClient.is_malicious(res):
                vt_url_hits.append({"url": u["url"], **res})
        else:
            vt_url_scores[u["url"]] = "not checked"

    vt_hash_scores, vt_attachment_hits = {}, []
    for att in attachment_result["attachments"]:
        sha256 = att.get("sha256")
        if not sha256:
            continue
        res = vt.check_hash(sha256)
        if res.get("checked") and res.get("found"):
            vt_hash_scores[sha256] = f"{res.get('malicious', 0)} engines"
            if VirusTotalClient.is_malicious(res):
                vt_attachment_hits.append({"sha256": sha256, **res})
        else:
            vt_hash_scores[sha256] = "not checked"

    # 10. MITRE ATT&CK mapping
    mitre_result = mitre_mapping.map_techniques(
        attachment_result, url_result, header_result, domain_result, auth_result
    )

    # 11. Risk scoring
    risk_result = risk_engine.compute_risk(
        header_result, auth_result, domain_result, url_result, ip_result,
        attachment_result, vt_url_hits, vt_attachment_hits, config,
    )

    # 12. Report generation
    report = report_generator.build_report(
        email_clean, header_result, auth_result, domain_result, url_result,
        ip_result, attachment_result, mitre_result, risk_result,
        vt_url_scores, vt_hash_scores,
    )

    base_name = os.path.splitext(os.path.basename(input_path))[0]
    json_path = os.path.join(out_dir, f"{base_name}_report.json")
    html_path = os.path.join(out_dir, f"{base_name}_report.html")
    report_generator.write_json(report, json_path)
    report_generator.write_html(report, email_clean, html_path)

    _print_summary(email_clean, risk_result, mitre_result, json_path, html_path)
    return report


def _print_summary(email_clean, risk_result, mitre_result, json_path, html_path):
    sev_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(risk_result["severity"], "white")

    console.print()
    console.print(f"[bold]Subject:[/bold] {email_clean['subject']}")
    console.print(f"[bold]From:[/bold] {email_clean['from']['address']}")
    console.print(f"[bold]Risk Score:[/bold] [{sev_color}]{risk_result['risk_score']}/100[/{sev_color}]")
    console.print(f"[bold]Severity:[/bold] [{sev_color}]{risk_result['severity']}[/{sev_color}]")

    table = Table(title="Indicators")
    table.add_column("Indicator")
    for ind in risk_result["indicators"]:
        table.add_row(ind)
    console.print(table)

    mitre_ids = ", ".join(t["technique_id"] for t in mitre_result)
    console.print(f"[bold]MITRE ATT&CK:[/bold] {mitre_ids}")
    console.print()
    console.print(f"[dim]JSON report:[/dim] {json_path}")
    console.print(f"[dim]HTML report:[/dim] {html_path}")


def main():
    parser = argparse.ArgumentParser(description="SOC Phishing Investigation Platform")
    parser.add_argument("--input", "-i", required=True, help="Path to .eml file to analyze")
    parser.add_argument("--config", "-c", default="config/config.yaml", help="Path to config.yaml")
    parser.add_argument("--out", "-o", default="reports", help="Output directory for reports")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        console.print(f"[red]Error:[/red] input file not found: {args.input}")
        sys.exit(1)

    run(args.input, args.config, args.out)


if __name__ == "__main__":
    main()
