from __future__ import annotations

import io

import pandas as pd
import plotly.express as px
import streamlit as st

from src.osint_sources import (
    combine_sources,
    fetch_cisa_kev,
    fetch_github_advisories,
    fetch_nvd_cves,
    fetch_security_rss,
    load_sample_iocs,
)
from src.scoring import add_scores

st.set_page_config(page_title="OSINT CTI Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ OSINT Cyber Threat Intelligence Dashboard")
st.caption(
    "Defensive CTI dashboard that aggregates public OSINT streams, prioritises indicators/advisories, "
    "and visualises threat trends for faster triage."
)

with st.sidebar:
    st.header("Collection settings")
    use_sample = st.checkbox("Load sample IOCs", value=True)
    use_cisa = st.checkbox("CISA Known Exploited Vulnerabilities", value=True)
    use_nvd = st.checkbox("NVD CVE keyword search", value=True)
    use_github = st.checkbox("GitHub Security Advisories", value=True)
    use_rss = st.checkbox("Security RSS/news feeds", value=True)

    keyword = st.text_input("NVD keyword", value="ransomware")
    ecosystem = st.selectbox("GitHub ecosystem", ["All", "pip", "npm", "maven", "go", "rubygems", "nuget", "composer"])
    limit = st.slider("Max records per source", 10, 100, 30, step=10)
    refresh = st.button("Refresh intelligence")


@st.cache_data(ttl=1800, show_spinner=False)
def collect_intelligence(
    sample: bool,
    cisa: bool,
    nvd: bool,
    github: bool,
    rss: bool,
    nvd_keyword: str,
    github_ecosystem: str,
    source_limit: int,
) -> pd.DataFrame:
    frames = []
    errors = []

    if sample:
        try:
            frames.append(load_sample_iocs())
        except Exception as exc:
            errors.append(f"Sample IOCs: {exc}")

    if cisa:
        try:
            frames.append(fetch_cisa_kev(limit=source_limit))
        except Exception as exc:
            errors.append(f"CISA KEV: {exc}")

    if nvd:
        try:
            frames.append(fetch_nvd_cves(keyword=nvd_keyword, limit=source_limit))
        except Exception as exc:
            errors.append(f"NVD: {exc}")

    if github:
        try:
            frames.append(fetch_github_advisories(limit=source_limit, ecosystem=github_ecosystem))
        except Exception as exc:
            errors.append(f"GitHub advisories: {exc}")

    if rss:
        try:
            frames.append(fetch_security_rss())
        except Exception as exc:
            errors.append(f"RSS feeds: {exc}")

    df = combine_sources(frames)
    df = add_scores(df)
    df.attrs["errors"] = errors
    return df


if refresh:
    st.cache_data.clear()

with st.spinner("Collecting public OSINT sources..."):
    intelligence = collect_intelligence(use_sample, use_cisa, use_nvd, use_github, use_rss, keyword, ecosystem, limit)

errors = intelligence.attrs.get("errors", []) if hasattr(intelligence, "attrs") else []
if errors:
    with st.expander("Source warnings"):
        for err in errors:
            st.warning(err)

if intelligence.empty:
    st.error("No intelligence records loaded. Enable at least one source or check your network connection.")
    st.stop()

# Filters
left, middle, right = st.columns(3)
with left:
    selected_priorities = st.multiselect(
        "Priority", sorted(intelligence["priority"].dropna().unique()), default=sorted(intelligence["priority"].dropna().unique())
    )
with middle:
    selected_types = st.multiselect(
        "Type", sorted(intelligence["type"].dropna().unique()), default=sorted(intelligence["type"].dropna().unique())
    )
with right:
    search = st.text_input("Search title, CVE, indicator, tag", value="")

filtered = intelligence[
    intelligence["priority"].isin(selected_priorities) & intelligence["type"].isin(selected_types)
].copy()
if search.strip():
    q = search.strip().lower()
    searchable = filtered[["indicator", "title", "description", "tags", "source"]].fillna("").agg(" ".join, axis=1).str.lower()
    filtered = filtered[searchable.str.contains(q, regex=False)]

# Summary cards
m1, m2, m3, m4 = st.columns(4)
m1.metric("Records", len(filtered))
m2.metric("Critical", int((filtered["priority"] == "Critical").sum()))
m3.metric("High", int((filtered["priority"] == "High").sum()))
m4.metric("Sources", filtered["source"].nunique())

# Visualisations
chart_col1, chart_col2 = st.columns(2)
with chart_col1:
    priority_counts = filtered["priority"].value_counts().reset_index()
    priority_counts.columns = ["priority", "count"]
    st.plotly_chart(px.bar(priority_counts, x="priority", y="count", title="Threat priority distribution"), use_container_width=True)

with chart_col2:
    source_counts = filtered["source"].value_counts().head(10).reset_index()
    source_counts.columns = ["source", "count"]
    st.plotly_chart(px.bar(source_counts, x="source", y="count", title="Records by OSINT source"), use_container_width=True)

st.subheader("Prioritised intelligence feed")
columns = [
    "priority_score",
    "priority",
    "indicator",
    "type",
    "source",
    "severity",
    "published",
    "title",
    "recommended_action",
    "url",
]
st.dataframe(filtered[[c for c in columns if c in filtered.columns]], use_container_width=True, hide_index=True)

st.subheader("Analyst view")
selected = st.selectbox("Select record for detail", filtered["indicator"].astype(str).head(200).tolist())
record = filtered[filtered["indicator"].astype(str) == selected].iloc[0]

st.markdown(f"### {record.get('title', selected)}")
st.write(f"**Indicator:** {record.get('indicator', '')}")
st.write(f"**Source:** {record.get('source', '')} | **Priority:** {record.get('priority', '')} ({record.get('priority_score', '')}/100)")
st.write(f"**Description:** {record.get('description', '')}")
st.write(f"**Recommended action:** {record.get('recommended_action', '')}")
if str(record.get("url", "")).startswith("http"):
    st.link_button("Open source record", record.get("url"))

csv_buffer = io.StringIO()
filtered.to_csv(csv_buffer, index=False)
st.download_button(
    label="Download filtered CTI CSV",
    data=csv_buffer.getvalue(),
    file_name="cti_export.csv",
    mime="text/csv",
)
