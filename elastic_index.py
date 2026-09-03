#!/usr/bin/env python3
"""
SIEM connector: indexes a generated investigation report (JSON) into
Elasticsearch/OpenSearch via the standard REST bulk/index API (no client
library dependency, just requests, so it works against either Elastic or
OpenSearch clusters).

Usage:
    python integrations/elastic_index.py --report reports/phish_report.json \
        --es-url https://elastic.example.com:9200 \
        --index phishing-investigations \
        --api-key <base64_api_key>
"""
import argparse
import json
import os
import sys

import requests


def push_report(report_path: str, es_url: str, index: str, api_key: str = None,
                 username: str = None, password: str = None, verify_ssl: bool = True) -> dict:
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    url = f"{es_url.rstrip('/')}/{index}/_doc"
    headers = {"Content-Type": "application/json"}
    auth = None

    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif username and password:
        auth = (username, password)

    resp = requests.post(url, headers=headers, auth=auth, data=json.dumps(report), verify=verify_ssl, timeout=15)
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="Index a phishing investigation JSON report into Elasticsearch/OpenSearch")
    parser.add_argument("--report", "-r", required=True)
    parser.add_argument("--es-url", default=os.environ.get("ES_URL"))
    parser.add_argument("--index", default=os.environ.get("ES_INDEX", "phishing-investigations"))
    parser.add_argument("--api-key", default=os.environ.get("ES_API_KEY"))
    parser.add_argument("--username", default=os.environ.get("ES_USERNAME"))
    parser.add_argument("--password", default=os.environ.get("ES_PASSWORD"))
    parser.add_argument("--no-verify-ssl", action="store_true")
    args = parser.parse_args()

    if not args.es_url:
        print("Error: --es-url (or ES_URL env var) is required.", file=sys.stderr)
        sys.exit(1)

    result = push_report(
        args.report, args.es_url, args.index,
        api_key=args.api_key, username=args.username, password=args.password,
        verify_ssl=not args.no_verify_ssl,
    )
    print(f"Indexed into Elasticsearch: {result}")


if __name__ == "__main__":
    main()
