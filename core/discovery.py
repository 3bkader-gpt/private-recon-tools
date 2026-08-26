"""
Discovery Engine
================
Fetches and discovers new private / embedded submission endpoints
for HackerOne and Bugcrowd from web archives and OSINT feeds.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List, Set

import httpx

BIN_DIR = Path(__file__).resolve().parent.parent / "bin"
WAYBACKURLS_BIN = BIN_DIR / "waybackurls.exe"


def discover_from_archive_org(domain: str, pattern: str) -> Set[str]:
    """Query web.archive.org CDX API directly."""
    cdx_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    found: Set[str] = set()
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(cdx_url)
            if resp.status_code == 200:
                rows = resp.json()
                for row in rows:
                    if row and isinstance(row, list):
                        url = row[0]
                        if re.search(pattern, url, re.I):
                            found.add(url.strip())
    except Exception as e:
        print(f"[!] Archive.org query error for {domain}: {e}")
    return found


def discover_from_alienvault(domain: str, pattern: str) -> Set[str]:
    """Query AlienVault OTX URL database."""
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1"
    found: Set[str] = set()
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(otx_url)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("url_list", []):
                    url = item.get("url", "")
                    if re.search(pattern, url, re.I):
                        found.add(url.strip())
    except Exception as e:
        print(f"[!] AlienVault query error for {domain}: {e}")
    return found


def discover_hackerone_urls() -> List[str]:
    pattern = r"hackerone\.com/[a-f0-9\-]+/embedded_submissions/new"
    urls = discover_from_archive_org("hackerone.com", pattern)
    urls.update(discover_from_alienvault("hackerone.com", pattern))
    return sorted(list(urls))


def discover_bugcrowd_urls() -> List[str]:
    pattern = r"bugcrowd\.com/[a-f0-9\-]+/external/report"
    urls = discover_from_archive_org("bugcrowd.com", pattern)
    urls.update(discover_from_alienvault("bugcrowd.com", pattern))
    return sorted(list(urls))
