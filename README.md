# OSINT Cyber Threat Intelligence Dashboard
A defensive Cyber Threat Intelligence (CTI) dashboard built with **Python** and **Streamlit**. The app aggregates public OSINT streams, normalises them into a single intelligence feed, calculates a triage priority score, and provides visualisations for quick security decision-making.

## Why this project exists
Security teams often receive information from multiple public sources: vulnerability catalogues, advisory databases, security news, and internal indicator lists. This project shows how those sources can be compiled into one lightweight analyst dashboard for faster triage.
This project is designed as a portfolio-quality cybersecurity engineering project. It is intentionally defensive and does not include exploit code.

## Features
- Aggregates public OSINT from:
  - CISA Known Exploited Vulnerabilities catalog
  - NVD CVE API 2.0 keyword search
  - GitHub Security Advisories
  - Security RSS/news feeds
  - Local sample IOC CSV
- Normalises CVEs, advisories, IOCs, and news into one table
- Computes a simple priority score using:
  - severity
  - recency
  - indicator type
  - CVSS score where available
  - keywords such as ransomware, exploited, RCE, phishing, malware
- Provides interactive Streamlit filters and charts
- Lets analysts export filtered CTI records as CSV
- Uses caching to reduce repeated API calls

## Tech stack
- Python
- Streamlit
- Pandas
- Requests
- Feedparser
- Plotly

## Project structure
```text
threat-intel-dashboard/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── .streamlit/
│   └── config.toml
├── sample_data/
│   └── iocs.csv
└── src/
    ├── __init__.py
    ├── config.py
    ├── osint_sources.py
    └── scoring.py
```

## Setup
Clone the repository and create a virtual environment:
```bash
git clone https://github.com/brindatenn/threat-intel-dashboard.git
cd threat-intel-dashboard
python -m venv .venv
```
Activate the environment:
1. Windows 
```bash
.venv\Scripts\activate
```
2. macOS/Linux
```bash
source .venv/bin/activate
```
Install dependencies:
```bash
pip install -r requirements.txt
```
Run the dashboard:
```bash
streamlit run app.py
```

## Optional API keys
The dashboard works without API keys, but NVD may rate-limit unauthenticated requests. If you have an NVD API key, store it locally as an environment variable:
### Windows
```bash
$env:NVD_API_KEY="your_key_here"
```
### macOS/Linux
```bash
export NVD_API_KEY="your_key_here"
```
Do not commit API keys to GitHub.

## Example use cases
- Quickly identify known exploited vulnerabilities from public advisories
- Search CVEs by keyword such as `ransomware`, `linux`, `vpn`, `wordpress`, or `authentication`
- Prioritise vulnerability/advisory records using a transparent scoring model
- Export filtered intelligence for reporting or further enrichment

## Limitations
This dashboard is a lightweight portfolio CTI tool, not a replacement for an enterprise SIEM, SOAR, EDR, or commercial threat intelligence platform. The scoring model is intentionally simple and transparent. In a production environment, it should be enriched with asset exposure, exploit maturity, internal telemetry, business criticality, and false-positive review.

## Disclaimer
This project is for defensive security monitoring, vulnerability awareness, and analyst triage. It does not perform exploitation, credential collection, malware execution, or unauthorised scanning.

