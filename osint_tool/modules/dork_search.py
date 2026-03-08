"""
dork_search.py — Google / Bing dork module.

Builds and fires targeted search dorks for:
  - General person lookup
  - Government documents (.gov, .gov.in, .gov.uk, court records, etc.)
  - Social media profiles
  - Leaked / pasted data
  - Professional records
"""

from __future__ import annotations

import time
import random
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import quote_plus

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dork templates
# ---------------------------------------------------------------------------

# Each template is a format string; {name}, {email}, {username}, {phone} are
# replaced at run-time.  Only templates whose placeholders are available will
# be rendered.

GENERAL_DORKS: List[str] = [
    '"{name}"',
    '"{name}" -site:facebook.com -site:twitter.com',
    '"{name}" filetype:pdf',
    '"{name}" filetype:doc OR filetype:docx',
    '"{name}" "resume" OR "curriculum vitae"',
    '"{name}" "address" OR "phone" OR "email"',
    '"{name}" "linkedin"',
    '"{name}" inurl:profile',
]

GOV_DORKS: List[str] = [
    '"{name}" site:.gov',
    '"{name}" site:.gov.in',
    '"{name}" site:.gov.uk',
    '"{name}" site:.gov.au',
    '"{name}" site:.gov.ca',
    '"{name}" site:.mil',
    '"{name}" site:court.gov OR site:judiciary.gov',
    '"{name}" site:pacer.gov',           # US federal court records
    '"{name}" site:publicaccess.courts.oregon.gov',
    '"{name}" site:apps.courts.state.va.us',
    '"{name}" site:sec.gov',             # US SEC filings
    '"{name}" site:fec.gov',             # US campaign finance
    '"{name}" site:fbi.gov OR site:dea.gov',
    '"{name}" site:irs.gov',
    '"{name}" site:ssa.gov',
    '"{name}" filetype:pdf site:.gov',
    '"{name}" "court record" OR "arrest record" OR "criminal record"',
    '"{name}" "voter registration" OR "registered voter"',
    '"{name}" "property record" OR "deed" OR "mortgage"',
    '"{name}" "bankruptcy" site:.gov OR site:pacer.gov',
    '"{name}" "sex offender" site:.gov',
    '"{name}" "government employee" site:.gov',
    '"{name}" "public record" OR "public information"',
    # India-specific
    '"{name}" site:eci.gov.in',          # Election Commission India
    '"{name}" site:mca.gov.in',          # Ministry of Corporate Affairs India
    '"{name}" site:mha.gov.in',          # Ministry of Home Affairs India
    # UK-specific
    '"{name}" site:companieshouse.gov.uk',
    # Generic court / legal
    '"{name}" "case number" OR "docket" filetype:pdf',
    '"{name}" "indictment" OR "conviction" OR "sentence"',
]

SOCIAL_DORKS: List[str] = [
    '"{name}" site:linkedin.com',
    '"{name}" site:twitter.com OR site:x.com',
    '"{name}" site:facebook.com',
    '"{name}" site:instagram.com',
    '"{name}" site:reddit.com',
    '"{name}" site:github.com',
    '"{name}" site:medium.com',
    '"{name}" site:quora.com',
    '"{name}" site:pinterest.com',
    '"{name}" site:tiktok.com',
]

LEAK_DORKS: List[str] = [
    '"{name}" site:pastebin.com',
    '"{name}" site:paste.ee',
    '"{name}" site:ghostbin.com',
    '"{name}" site:rentry.co',
    '"{name}" "leaked" OR "dump" OR "breach"',
    '"{name}" "password" OR "hash" filetype:txt',
]

EMAIL_DORKS: List[str] = [
    '"{email}"',
    '"{email}" site:.gov',
    '"{email}" site:linkedin.com',
    '"{email}" "password" OR "breach" OR "leaked"',
    '"{email}" site:pastebin.com',
    'intext:"{email}"',
]

USERNAME_DORKS: List[str] = [
    '"{username}" site:github.com',
    '"{username}" site:twitter.com OR site:x.com',
    '"{username}" site:reddit.com',
    '"{username}" site:linkedin.com',
    '"{username}" site:instagram.com',
    '"{username}" inurl:"{username}"',
]

PHONE_DORKS: List[str] = [
    '"{phone}"',
    '"{phone}" site:.gov',
    '"{phone}" "name" OR "address" OR "owner"',
    '"{phone}" site:pastebin.com',
    'intext:"{phone}"',
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DorkResult:
    engine: str
    dork: str
    url: str
    title: str
    snippet: str


@dataclass
class DorkSearchResult:
    name: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    results: List[DorkResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "email": self.email,
            "username": self.username,
            "phone": self.phone,
            "results": [vars(r) for r in self.results],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]


def _headers() -> dict:
    return {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }


def _google_search(query: str, session: requests.Session, max_results: int = 10) -> List[dict]:
    """
    Perform a single Google web search via the public HTML interface.
    Returns a list of {title, url, snippet} dicts.

    Note: Google may rate-limit or return a CAPTCHA for automated queries.
    A short random sleep is inserted between requests to be polite.
    """
    url = "https://www.google.com/search"
    params = {"q": query, "num": max_results, "hl": "en"}
    results: List[dict] = []
    try:
        resp = session.get(url, params=params, headers=_headers(), timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        for g in soup.select("div.g"):
            anchor = g.select_one("a[href]")
            title_tag = g.select_one("h3")
            snippet_tag = g.select_one("div.VwiC3b") or g.select_one("span.st")
            if anchor and title_tag:
                href = anchor["href"]
                if href.startswith("/url?q="):
                    href = href[7:].split("&")[0]
                results.append({
                    "title": title_tag.get_text(strip=True),
                    "url": href,
                    "snippet": snippet_tag.get_text(strip=True) if snippet_tag else "",
                })
    except requests.RequestException as exc:
        logger.warning("Google search failed for %r: %s", query, exc)
    return results


def _bing_search(query: str, session: requests.Session, max_results: int = 10) -> List[dict]:
    """
    Perform a single Bing web search via the public HTML interface.
    """
    url = "https://www.bing.com/search"
    params = {"q": query, "count": max_results}
    results: List[dict] = []
    try:
        resp = session.get(url, params=params, headers=_headers(), timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        for li in soup.select("li.b_algo"):
            anchor = li.select_one("h2 a")
            snippet_tag = li.select_one("div.b_caption p") or li.select_one("p")
            if anchor:
                results.append({
                    "title": anchor.get_text(strip=True),
                    "url": anchor.get("href", ""),
                    "snippet": snippet_tag.get_text(strip=True) if snippet_tag else "",
                })
    except requests.RequestException as exc:
        logger.warning("Bing search failed for %r: %s", query, exc)
    return results


def _render_dork(template: str, **kwargs) -> Optional[str]:
    """Return a rendered dork string, or None if required placeholders are missing."""
    try:
        return template.format(**kwargs)
    except KeyError:
        return None


def _fire_dorks(
    templates: List[str],
    engine_fn,
    engine_name: str,
    session: requests.Session,
    delay: float = 2.0,
    **kwargs,
) -> List[DorkResult]:
    out: List[DorkResult] = []
    for tmpl in templates:
        dork = _render_dork(tmpl, **kwargs)
        if dork is None:
            continue
        hits = engine_fn(dork, session)
        for h in hits:
            out.append(DorkResult(
                engine=engine_name,
                dork=dork,
                url=h["url"],
                title=h["title"],
                snippet=h["snippet"],
            ))
        time.sleep(delay + random.uniform(0, 1.5))
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_dork_search(
    name: Optional[str] = None,
    email: Optional[str] = None,
    username: Optional[str] = None,
    phone: Optional[str] = None,
    use_gov_dorks: bool = True,
    use_social_dorks: bool = True,
    use_leak_dorks: bool = True,
    engine: str = "google",
    delay: float = 2.5,
    max_results_per_dork: int = 10,
) -> DorkSearchResult:
    """
    Run a comprehensive dork-based OSINT search.

    Args:
        name: Full name of the target person.
        email: Target email address.
        username: Target username / handle.
        phone: Target phone number (international format preferred).
        use_gov_dorks: Include government document dorks.
        use_social_dorks: Include social media dorks.
        use_leak_dorks: Include paste/leak site dorks.
        engine: "google", "bing", or "both".
        delay: Seconds between requests (be polite).
        max_results_per_dork: Max hits per individual dork.

    Returns:
        DorkSearchResult containing all hits.
    """
    result = DorkSearchResult(name=name, email=email, username=username, phone=phone)

    kwargs: dict = {}
    if name:
        kwargs["name"] = name
    if email:
        kwargs["email"] = email
    if username:
        kwargs["username"] = username
    if phone:
        kwargs["phone"] = phone

    if not kwargs:
        result.errors.append("At least one of name/email/username/phone is required.")
        return result

    session = requests.Session()
    session.headers.update({"Accept-Encoding": "gzip, deflate, br"})

    engines = []
    if engine in ("google", "both"):
        engines.append((_google_search, "Google"))
    if engine in ("bing", "both"):
        engines.append((_bing_search, "Bing"))
    if not engines:
        result.errors.append(f"Unknown engine: {engine!r}. Use 'google', 'bing', or 'both'.")
        return result

    # Build the set of dork templates to use
    active_templates: List[str] = []

    if name:
        active_templates.extend(GENERAL_DORKS)
        if use_gov_dorks:
            active_templates.extend(GOV_DORKS)
        if use_social_dorks:
            active_templates.extend(SOCIAL_DORKS)
        if use_leak_dorks:
            active_templates.extend(LEAK_DORKS)

    if email:
        active_templates.extend(EMAIL_DORKS)

    if username:
        active_templates.extend(USERNAME_DORKS)

    if phone:
        active_templates.extend(PHONE_DORKS)

    # De-duplicate
    active_templates = list(dict.fromkeys(active_templates))

    for engine_fn, engine_name in engines:
        logger.info("Running %d dorks on %s …", len(active_templates), engine_name)
        hits = _fire_dorks(
            active_templates,
            engine_fn,
            engine_name,
            session,
            delay=delay,
            **kwargs,
        )
        result.results.extend(hits)

    return result


def build_dork_urls(
    name: Optional[str] = None,
    email: Optional[str] = None,
    username: Optional[str] = None,
    phone: Optional[str] = None,
    gov_only: bool = False,
) -> List[str]:
    """
    Return a list of ready-to-open Google search URLs for the supplied identifiers.
    Useful for quick copy-paste into a browser without firing automated requests.
    """
    kwargs: dict = {}
    if name:
        kwargs["name"] = name
    if email:
        kwargs["email"] = email
    if username:
        kwargs["username"] = username
    if phone:
        kwargs["phone"] = phone

    templates = GOV_DORKS if gov_only else (GENERAL_DORKS + GOV_DORKS + SOCIAL_DORKS + LEAK_DORKS)
    if email:
        templates += EMAIL_DORKS
    if username:
        templates += USERNAME_DORKS
    if phone:
        templates += PHONE_DORKS

    urls = []
    for tmpl in templates:
        dork = _render_dork(tmpl, **kwargs)
        if dork:
            urls.append(f"https://www.google.com/search?q={quote_plus(dork)}")
    return urls
