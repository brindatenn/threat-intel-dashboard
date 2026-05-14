"""Simple CTI prioritisation logic for defensive triage."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pandas as pd

SEVERITY_POINTS = {
    "critical": 35,
    "high": 25,
    "medium": 15,
    "low": 8,
    "known_exploited": 40,
    "informational": 3,
    "unknown": 5,
}

KEYWORD_POINTS = {
    "ransomware": 20,
    "exploited": 20,
    "zero-day": 20,
    "0-day": 20,
    "remote code execution": 18,
    "rce": 18,
    "privilege escalation": 14,
    "credential": 12,
    "phishing": 12,
    "malware": 12,
    "supply-chain": 12,
    "critical": 10,
}

TYPE_POINTS = {
    "cve": 12,
    "advisory": 10,
    "ip": 8,
    "domain": 8,
    "url": 8,
    "news": 2,
}


def _text_blob(row: pd.Series) -> str:
    return " ".join(str(row.get(col, "")) for col in ["title", "description", "tags", "severity"]).lower()


def _recency_points(value) -> int:
    dt = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(dt):
        return 0
    days = (datetime.now(timezone.utc) - dt.to_pydatetime()).days
    if days <= 7:
        return 18
    if days <= 30:
        return 12
    if days <= 90:
        return 6
    return 0


def score_row(row: pd.Series) -> int:
    severity = str(row.get("severity", "unknown")).lower()
    score = SEVERITY_POINTS.get(severity, 5)
    score += TYPE_POINTS.get(str(row.get("type", "")).lower(), 0)
    score += _recency_points(row.get("published_dt", row.get("published")))

    cvss = row.get("cvss_score")
    try:
        if pd.notna(cvss):
            score += int(float(cvss) * 3)
    except Exception:
        pass

    text = _text_blob(row)
    for keyword, points in KEYWORD_POINTS.items():
        if keyword in text:
            score += points

    # CVE pattern gives a small extra triage signal because it is directly actionable.
    if re.search(r"CVE-\d{4}-\d{4,}", str(row.get("indicator", "")), flags=re.I):
        score += 5

    return min(score, 100)


def add_scores(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    out = df.copy()
    out["priority_score"] = out.apply(score_row, axis=1)
    out["priority"] = pd.cut(
        out["priority_score"],
        bins=[-1, 29, 59, 79, 100],
        labels=["Low", "Medium", "High", "Critical"],
    ).astype(str)
    return out.sort_values(["priority_score", "published_dt"], ascending=[False, False])
