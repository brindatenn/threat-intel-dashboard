"""Configuration for public OSINT sources used by the dashboard."""

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# NVD CVE API 2.0 endpoint. An API key is optional but recommended for higher rate limits.
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# GitHub global security advisories endpoint.
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"

RSS_FEEDS = {
    "CISA Alerts": "https://www.cisa.gov/news-events/cybersecurity-advisories/all.xml",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
}
