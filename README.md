#  Phishing Investigation Platform

An automated **SOC Phishing Investigation Tool** that ingests a raw `.eml` file
and produces a full triage report: sender/authentication analysis, IOC
extraction and enrichment, YARA scanning, MITRE ATT&CK mapping, and a
weighted risk score — in seconds, not the 20+ minutes a manual triage takes.

```
Risk Score: 87/100
Severity: HIGH
Indicators:
  - Suspicious Sender
  - Newly Registered Domain
  - Malicious URL
  - Attachment Hash
```

---

## Why this exists

Tier-1 SOC analysts spend a huge share of their day on repetitive phishing
triage: opening the email, eyeballing headers, checking SPF/DKIM/DMARC,
defanging and looking up URLs, hashing attachments, pivoting to VirusTotal,
then writing it all up. This tool automates every one of those steps and
produces an analyst-ready report so humans can spend their time on
judgment calls, not data collection.

---

## Architecture

```
Email (.eml)
  │
  ├── Sender Analysis          → display-name spoofing, Reply-To/Return-Path mismatch, lookalike domains
  ├── SPF                      → Authentication-Results + live DNS TXT cross-check
  ├── DKIM                     → Authentication-Results verdict / signature presence
  ├── DMARC                    → Authentication-Results + live DNS policy lookup
  ├── Header Analysis          → Received chain, mailer/UA anomalies
  ├── URL Extraction           → plaintext + HTML, display-text vs href mismatch, shorteners
  ├── Domain Reputation        → WHOIS age check, suspicious TLDs, lexical heuristics
  ├── IP Reputation            → DNS resolution + AbuseIPDB confidence score
  ├── Attachment Hash          → MD5 / SHA1 / SHA256 + risky extensions
  ├── VirusTotal               → hash / URL / domain / IP reputation (API v3)
  └── MITRE Mapping            → deterministic rule table → ATT&CK technique IDs
  │
  ▼
Risk Engine  →  Risk Score (0-100) + Severity (LOW / MEDIUM / HIGH)
  │
  ▼
Report Generator  →  JSON (SIEM/SOAR-ready) + HTML (analyst-ready)
```

## SOC Workflow this project follows

This tool is built and documented the way a SOC detection-engineering
project should be — from simulated attack to lessons learned:

```
Attack Simulation        (sample_phishing.eml — realistic spoofed/lure email)
       ↓
Telemetry Collection      (.eml ingestion, header + body + attachment parsing)
       ↓
Detection Engineering     (YARA rules, lexical/heuristic detections in src/)
       ↓
SIEM Correlation          (JSON report designed for SIEM/SOAR ingestion)
       ↓
Alert Triage               (automated risk scoring → severity banding)
       ↓
Threat Intelligence        (VirusTotal, AbuseIPDB, WHOIS enrichment)
       ↓
MITRE ATT&CK Mapping       (deterministic technique mapping)
       ↓
Incident Investigation     (full HTML/JSON investigation report)
       ↓
Containment                 (recommended-actions section, analyst-driven)
       ↓
Lessons Learned             (extend YARA rules / brand list / weights over time)
       ↓
SOC Investigation Report
```

---

## Project structure

```
phishing-investigation-platform/
├── main.py                     # CLI entrypoint / pipeline orchestrator
├── src/
│   ├── config.py                # YAML + env-var config loader
│   ├── eml_parser.py            # .eml → structured dict
│   ├── header_analysis.py       # sender spoofing / lookalike domain checks
│   ├── auth_analysis.py         # SPF / DKIM / DMARC
│   ├── url_extractor.py         # URL extraction + href/display mismatch
│   ├── domain_reputation.py     # WHOIS age + TLD heuristics
│   ├── ip_reputation.py         # DNS resolution + AbuseIPDB
│   ├── attachment_analysis.py   # hashing + YARA scanning
│   ├── virustotal_client.py     # VirusTotal API v3 wrapper
│   ├── mitre_mapping.py         # indicator → ATT&CK technique rules
│   ├── risk_engine.py           # weighted scoring → severity
│   └── report_generator.py      # JSON + HTML report rendering
├── yara_rules/phishing_rules.yar
├── templates/report_template.html
├── webapp/                      # Flask drag-and-drop UI
│   ├── app.py
│   └── templates/index.html
├── integrations/
│   ├── splunk_hec.py             # push JSON reports to Splunk HEC
│   └── elastic_index.py          # push JSON reports to Elasticsearch/OpenSearch
├── batch_scan.py                # sweep a folder of .eml files
├── Dockerfile / docker-compose.yml
├── .github/workflows/ci.yml     # test suite on 3.10/3.11/3.12
├── config/config.example.yaml   # copy → config.yaml, fill in API keys
├── tests/                        # sample fixture + pytest suite
└── reports/                     # generated reports land here (git-ignored)
```

---

## Setup

```bash
git clone https://github.com/<your-username>/phishing-investigation-platform.git
cd phishing-investigation-platform

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp config/config.example.yaml config/config.yaml
# edit config/config.yaml and add your VirusTotal / AbuseIPDB API keys (optional)
```

> All enrichment steps degrade gracefully with no API key — they're skipped
> rather than crashing the pipeline, so the tool is fully usable offline for
> header/auth/YARA-only triage.

## Usage

```bash
python main.py --input path/to/email.eml
python main.py --input path/to/email.eml --config config/config.yaml --out reports/
```

Try it against the included sample:

```bash
python main.py --input tests/sample_phishing.eml
```

This prints a live triage summary to the terminal and writes two reports to
`reports/`:

- `<name>_report.json` — full structured findings, ready for SIEM/SOAR ingestion
- `<name>_report.html` — analyst-facing visual report (see example below)

<p align="center"><em>Score panel · Sender analysis · SPF/DKIM/DMARC · URL &amp; domain/IP reputation · Attachment hashes &amp; YARA hits · MITRE ATT&amp;CK chips</em></p>

---

## Web UI (drag-and-drop)

A minimal Flask app for analysts who'd rather drop a file in a browser than
run a CLI:

```bash
pip install -r requirements.txt
python webapp/app.py
# open http://localhost:5000, drag an .eml file in, get the same HTML report
```

## Docker

```bash
docker compose up --build
# open http://localhost:5000
```

Or run the CLI one-off inside the container:

```bash
docker build -t phishing-investigation-platform .
docker run --rm -v $(pwd)/tests:/app/tests phishing-investigation-platform \
    python main.py --input tests/sample_phishing.eml
```

## SIEM integration

`integrations/splunk_hec.py` and `integrations/elastic_index.py` push a
generated JSON report straight into Splunk (via HTTP Event Collector) or
Elasticsearch/OpenSearch, so triage results land in your SIEM automatically:

```bash
python main.py --input samples/phish.eml
python integrations/splunk_hec.py --report reports/phish_report.json \
    --hec-url https://splunk.example.com:8088/services/collector/event \
    --hec-token <token>

python integrations/elastic_index.py --report reports/phish_report.json \
    --es-url https://elastic.example.com:9200 --index phishing-investigations \
    --api-key <base64_api_key>
```

---

## Risk scoring model

Each detected indicator adds a weight to a 0–100 score (capped at 100):

Indicator                        | Weight |
|-----------------------------------|:------:|
Suspicious Sender                 | 20     
SPF/DKIM/DMARC Failure            | 12     
Newly Registered Domain           | 20     
Malicious URL (VirusTotal)        | 25     
Suspicious Link (display/href)    | 8      
Malicious Attachment (VT/YARA)    | 25     
Risky Attachment Extension        | 10     
Malicious IP (AbuseIPDB)          | 10     
Header Anomaly                    | 5      

Score   | Severity |
|-----------------------------------|
≥ 70    | HIGH     
40–69   | MEDIUM   
< 40    | LOW      

Weights and thresholds are fully configurable in `config/config.yaml`.

## MITRE ATT&CK techniques covered

`T1566` Phishing · `T1566.001` Spearphishing Attachment · `T1566.002`
Spearphishing Link · `T1204.001/.002` User Execution · `T1059.001`
PowerShell · `T1036.007` Double Extension Masquerading · `T1027.006`
Archive/HTML Smuggling · `T1583.001` Acquire Infrastructure: Domains ·
`T1585.002` Establish Accounts: Email · `T1078` Valid Accounts · `T1656`
Impersonation

## Detection engineering (YARA)

`yara_rules/phishing_rules.yar` ships baseline rules for macro-enabled
Office droppers, HTML credential-harvesting forms, obfuscated PowerShell,
script droppers (`.js`/`.wsf`/`.hta`), double-extension masquerading, and
password-protected ZIP lures. Extend this file with rules tuned to your own
telemetry — it's the "Detection Engineering" and "Lessons Learned" stage of
the workflow above.

---

## Roadmap / extension ideas

- [ ] SOAR playbook integration (auto-quarantine, auto-block sender domain)
- [ ] OSINT pivot via AlienVault OTX / URLhaus
- [ ] PDF report export
- [x] Web UI (Flask) for drag-and-drop `.eml` upload — see `webapp/`
- [x] Bulk/batch mode for mailbox-wide sweeps — see `batch_scan.py`
- [x] SIEM connector (Splunk HEC / Elastic) for direct JSON ingestion — see `integrations/`
- [x] Docker/docker-compose deployment

## Disclaimer

This tool is a **triage aid**, not an autonomous responder. All containment
actions (blocking senders/domains, quarantining mail, disabling accounts)
should be reviewed and executed by a human analyst. Risk scores are
heuristic, not ground truth — always validate HIGH/MEDIUM verdicts before
acting on them.


