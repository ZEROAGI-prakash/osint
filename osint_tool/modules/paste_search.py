"""
paste_search.py — Paste site OSINT module.

Searches public paste / data-dump sites for mentions of a target.

Services used (all free, no API keys):
  - Psbdmp.ws  — public Pastebin dumps search API
  - SnusBase public search (limited)
  - Google dork (delegated to dork_search module)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PasteEntry:
    source: str
    url: str
    title: str
    date: Optional[str] = None
    snippet: Optional[str] = None


@dataclass
class PasteSearchResult:
    query: str
    entries: List[PasteEntry] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "entries": [vars(e) for e in self.entries],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Source: psbdmp.ws (indexes public Pastebin pastes)
# ---------------------------------------------------------------------------

def _search_psbdmp(query: str, session: requests.Session) -> List[PasteEntry]:
    entries: List[PasteEntry] = []
    url = "https://psbdmp.ws/api/v3/search"
    try:
        resp = session.get(url, params={"q": query}, timeout=15, headers=_HEADERS)
        if resp.status_code != 200:
            return entries
        data = resp.json()
        for item in data.get("data", []):
            pid = item.get("id", "")
            entries.append(PasteEntry(
                source="psbdmp (Pastebin)",
                url=f"https://pastebin.com/{pid}",
                title=item.get("tags", ""),
                date=item.get("time", ""),
                snippet=item.get("text", "")[:200] if item.get("text") else None,
            ))
    except Exception as exc:
        logger.warning("psbdmp search failed: %s", exc)
    return entries


# ---------------------------------------------------------------------------
# Source: paste.ee public search
# ---------------------------------------------------------------------------

def _search_paste_ee(query: str, session: requests.Session) -> List[PasteEntry]:
    entries: List[PasteEntry] = []
    try:
        resp = session.get(
            "https://paste.ee/search",
            params={"q": query, "page": 1},
            headers=_HEADERS,
            timeout=15,
        )
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        for item in soup.select("div.paste-item"):
            title_tag = item.select_one("a.paste-title")
            snippet_tag = item.select_one("div.paste-snippet")
            if title_tag:
                href = title_tag.get("href", "")
                entries.append(PasteEntry(
                    source="paste.ee",
                    url=href if href.startswith("http") else f"https://paste.ee{href}",
                    title=title_tag.get_text(strip=True),
                    snippet=snippet_tag.get_text(strip=True)[:200] if snippet_tag else None,
                ))
    except Exception as exc:
        logger.warning("paste.ee search failed: %s", exc)
    return entries


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_paste_search(query: str) -> PasteSearchResult:
    """
    Search public paste sites for a given query string.

    Args:
        query: Name, email, username, or any identifier to search.

    Returns:
        PasteSearchResult with all found paste entries.
    """
    result = PasteSearchResult(query=query)
    session = requests.Session()

    try:
        result.entries.extend(_search_psbdmp(query, session))
    except Exception as exc:
        result.errors.append(f"psbdmp: {exc}")

    try:
        result.entries.extend(_search_paste_ee(query, session))
    except Exception as exc:
        result.errors.append(f"paste.ee: {exc}")

    return result
