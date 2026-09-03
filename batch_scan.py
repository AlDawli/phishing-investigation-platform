#!/usr/bin/env python3
"""
Batch mode: run the pipeline across every .eml file in a directory and print
a consolidated triage summary sorted by risk score, highest first. Useful
for sweeping a mailbox export or a folder of user-reported phishing emails.

Usage:
    python batch_scan.py --input-dir samples/ --out reports/
"""
import argparse
import glob
import os
import sys

from rich.console import Console
from rich.table import Table

sys.path.insert(0, os.path.dirname(__file__))
from main import run  # reuses the single-email pipeline

console = Console()


def main():
    parser = argparse.ArgumentParser(description="Batch phishing triage across a folder of .eml files")
    parser.add_argument("--input-dir", "-d", required=True)
    parser.add_argument("--config", "-c", default="config/config.yaml")
    parser.add_argument("--out", "-o", default="reports")
    args = parser.parse_args()

    eml_files = sorted(glob.glob(os.path.join(args.input_dir, "*.eml")))
    if not eml_files:
        console.print(f"[yellow]No .eml files found in {args.input_dir}[/yellow]")
        return

    summary_rows = []
    for path in eml_files:
        try:
            report = run(path, args.config, args.out)
            summary_rows.append((
                os.path.basename(path),
                report["risk"]["risk_score"],
                report["risk"]["severity"],
                report["email"]["subject"],
            ))
        except Exception as exc:
            console.print(f"[red]Failed to process {path}: {exc}[/red]")

    summary_rows.sort(key=lambda r: r[1], reverse=True)

    table = Table(title="Batch Triage Summary")
    table.add_column("File")
    table.add_column("Score")
    table.add_column("Severity")
    table.add_column("Subject")
    for row in summary_rows:
        sev_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(row[2], "white")
        table.add_row(row[0], str(row[1]), f"[{sev_color}]{row[2]}[/{sev_color}]", row[3])

    console.rule("[bold]Batch Summary")
    console.print(table)


if __name__ == "__main__":
    main()
