"""OSINT collection helpers.

The project uses public, defensive intelligence sources only. API keys are optional
and should be stored in Streamlit secrets or environment variables, not committed.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import feedparser
import pandas as pd
import requests

from .config import CISA_KEV_URL, GITHUB_ADVISORIES_URL, NVD_CVE_API_URL, RSS_FEEDS

REQUEST_TIMEOUT = 12
USER_AGENT = "Brinda-CTI-Dashboard/1.0 defensive-security-research"


def _get_json(url: str, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> Any:
    merged_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        merged_headers.update(headers)
    response = requests.get(url, params=params, headers=merged_headers, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.json()


def fetch_cisa_kev(limit: int = 100) -> pd.DataFrame:
    """Fetch CISA Known Exploited Vulnerabilities and normalise to a table."""
    data = _get_json(CISA_KEV_URL)
    rows = data.get("vulnerabilities", [])[:limit]
    records = []
    for item in rows:
        records.append(
            {
                "indicator": item.get("cveID"),
                "type": "cve",
                "source": "CISA KEV",
                "title": f"{item.get('vendorProject', '')} {item.get('product', '')}".strip(),
                "severity": "known_exploited",
                "published": item.get("dateAdded"),
                "description": item.get("shortDescription", ""),
                "recommended_action": item.get("requiredAction", ""),
                "tags": "known-exploited, vulnerability",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        )
    return pd.DataFrame.from_records(records)


def fetch_nvd_cves(keyword: str = "ransomware", limit: int = 20, api_key: str | None = None) -> pd.DataFrame:
    """Fetch recent or keyword-matching CVEs from NVD API 2.0."""
    params = {"keywordSearch": keyword, "resultsPerPage": min(limit, 50)}
    headers = {}
    token = api_key or os.getenv("NVD_API_KEY")
    if token:
        headers["apiKey"] = token

    data = _get_json(NVD_CVE_API_URL, params=params, headers=headers)
    records = []
    for wrapper in data.get("vulnerabilities", []):
        cve = wrapper.get("cve", {})
        metrics = cve.get("metrics", {})
        score = None
        severity = "unknown"
        if metrics.get("cvssMetricV31"):
            cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity", "unknown")
        elif metrics.get("cvssMetricV30"):
            cvss = metrics["cvssMetricV30"][0].get("cvssData", {})
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity", "unknown")
        descriptions = cve.get("descriptions", [])
        english_description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        records.append(
            {
                "indicator": cve.get("id"),
                "type": "cve",
                "source": "NVD",
                "title": cve.get("id"),
                "severity": severity,
                "cvss_score": score,
                "published": cve.get("published"),
                "description": english_description,
                "recommended_action": "Review affected products and apply vendor remediation.",
                "tags": "vulnerability, nvd",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
            }
        )
    return pd.DataFrame.from_records(records)


def fetch_github_advisories(limit: int = 30, ecosystem: str | None = None) -> pd.DataFrame:
    """Fetch GitHub-reviewed global security advisories."""
    params: dict[str, Any] = {"per_page": min(limit, 100), "type": "reviewed"}
    if ecosystem and ecosystem != "All":
        params["ecosystem"] = ecosystem
    data = _get_json(GITHUB_ADVISORIES_URL, params=params)
    records = []
    for item in data:
        cve = item.get("cve_id") or item.get("ghsa_id")
        records.append(
            {
                "indicator": cve,
                "type": "advisory",
                "source": "GitHub Advisory Database",
                "title": item.get("summary"),
                "severity": item.get("severity", "unknown"),
                "published": item.get("published_at"),
                "description": item.get("description", ""),
                "recommended_action": "Review patched versions and upgrade affected packages.",
                "tags": f"github-advisory,{item.get('ecosystem', '')}",
                "url": item.get("html_url"),
            }
        )
    return pd.DataFrame.from_records(records)


def fetch_security_rss() -> pd.DataFrame:
    """Fetch cyber-security news/advisory RSS feeds."""
    records = []
    for source, feed_url in RSS_FEEDS.items():
        parsed = feedparser.parse(feed_url)
        for entry in parsed.entries[:20]:
            published = entry.get("published", entry.get("updated", ""))
            records.append(
                {
                    "indicator": entry.get("link", entry.get("title")),
                    "type": "news",
                    "source": source,
                    "title": entry.get("title", "Untitled"),
                    "severity": "informational",
                    "published": published,
                    "description": entry.get("summary", ""),
                    "recommended_action": "Review for relevance to your environment.",
                    "tags": "news, advisory",
                    "url": entry.get("link"),
                }
            )
    return pd.DataFrame.from_records(records)


def load_sample_iocs(path: str = "sample_data/iocs.csv") -> pd.DataFrame:
    df = pd.read_csv(path)
    df["title"] = df["indicator"]
    df["severity"] = df["confidence"]
    df["published"] = df["first_seen"]
    df["recommended_action"] = "Triage indicator, enrich with internal telemetry, and block only after validation."
    df["url"] = ""
    return df


def combine_sources(frames: list[pd.DataFrame]) -> pd.DataFrame:
    cleaned = [df for df in frames if df is not None and not df.empty]
    if not cleaned:
        return pd.DataFrame()
    df = pd.concat(cleaned, ignore_index=True)
    df["collected_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    df["published_dt"] = pd.to_datetime(df.get("published"), errors="coerce", utc=True)
    df = df.drop_duplicates(subset=["indicator", "source"], keep="first")
    return df
