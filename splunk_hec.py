#!/usr/bin/env python3
"""
SIEM connector: pushes a generated investigation report (JSON) into Splunk
via HTTP Event Collector (HEC). Run this after main.py, or wire it into
your own automation (e.g. call push_report() right after report_generator
writes the JSON in a custom pipeline).

Usage:
    python integrations/splunk_hec.py --report reports/phish_report.json \
        --hec-url https://splunk.example.com:8088/services/collector/event \
        --hec-token <token>

    # or via env vars:
    export SPLUNK_HEC_URL=https://splunk.example.com:8088/services/collector/event
    export SPLUNK_HEC_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    python integrations/splunk_hec.py --report reports/phish_report.json
"""
import argparse
import json
import os
import sys

import requests


def push_report(report_path: str, hec_url: str, hec_token: str, source: str = "phishing-investigation-platform",
                 sourcetype: str = "phishing:investigation", index: str = None, verify_ssl: bool = True) -> dict:
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    event = {
        "event": report,
        "sourcetype": sourcetype,
        "source": source,
    }
    if index:
        event["index"] = index

    headers = {"Authorization": f"Splunk {hec_token}", "Content-Type": "application/json"}
    resp = requests.post(hec_url, headers=headers, data=json.dumps(event), verify=verify_ssl, timeout=15)
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="Push a phishing investigation JSON report to Splunk HEC")
    parser.add_argument("--report", "-r", required=True, help="Path to the *_report.json file")
    parser.add_argument("--hec-url", default=os.environ.get("SPLUNK_HEC_URL"))
    parser.add_argument("--hec-token", default=os.environ.get("SPLUNK_HEC_TOKEN"))
    parser.add_argument("--index", default=os.environ.get("SPLUNK_INDEX"))
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS verification (self-signed labs only)")
    args = parser.parse_args()

    if not args.hec_url or not args.hec_token:
        print("Error: --hec-url/--hec-token (or SPLUNK_HEC_URL/SPLUNK_HEC_TOKEN env vars) are required.", file=sys.stderr)
        sys.exit(1)

    result = push_report(
        args.report, args.hec_url, args.hec_token,
        index=args.index, verify_ssl=not args.no_verify_ssl,
    )
    print(f"Pushed to Splunk HEC: {result}")


if __name__ == "__main__":
    main()
