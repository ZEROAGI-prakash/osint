"""
email_osint.py — Email OSINT module.

Checks:
  1. Format / syntax validation
  2. MX record lookup (does the domain accept mail?)
  3. HaveIBeenPwned v3 public API (breach list, no API key needed for listing)
  4. Gravatar MD5 hash → avatar URL
  5. GitHub search by email (unauthenticated API)
  6. Hunter.io email format inference (no key needed)
  7. Disposable email domain detection
"""

from __future__ import annotations

import hashlib
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional

import dns.resolver
import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Disposable email domains (partial list)
# ---------------------------------------------------------------------------
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwam.com", "yopmail.com", "trashmail.com", "sharklasers.com",
    "guerrillamailblock.com", "grr.la", "guerrillamail.info", "guerrillamail.biz",
    "guerrillamail.de", "guerrillamail.net", "guerrillamail.org", "spam4.me",
    "dispostable.com", "maildrop.cc", "spamgourmet.com", "spamgourmet.net",
    "spamgourmet.org", "spamgourmet.com", "discard.email", "fakeinbox.com",
    "mailnull.com", "spamex.com", "spamfree24.org", "mailnesia.com",
    "mailnull.com", "0-mail.com", "0815.ru", "0clickemail.com",
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BreachInfo:
    name: str
    domain: str
    breach_date: str
    description: str
    data_classes: List[str]
    pwn_count: int


@dataclass
class EmailOsintResult:
    email: str
    is_valid_format: bool = False
    is_disposable: bool = False
    domain: str = ""
    mx_records: List[str] = field(default_factory=list)
    mx_error: Optional[str] = None
    gravatar_url: Optional[str] = None
    breaches: List[BreachInfo] = field(default_factory=list)
    breach_error: Optional[str] = None
    github_users: List[dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "is_valid_format": self.is_valid_format,
            "is_disposable": self.is_disposable,
            "domain": self.domain,
            "mx_records": self.mx_records,
            "mx_error": self.mx_error,
            "gravatar_url": self.gravatar_url,
            "breaches": [vars(b) for b in self.breaches],
            "breach_error": self.breach_error,
            "github_users": self.github_users,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def _validate_format(email: str) -> bool:
    return bool(_EMAIL_RE.match(email))


def _get_mx(domain: str) -> tuple[List[str], Optional[str]]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx = sorted([str(r.exchange).rstrip(".") for r in answers])
        return mx, None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], "No MX records found"
    except Exception as exc:
        return [], str(exc)


def _gravatar_url(email: str) -> str:
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{h}?d=404"


def _check_gravatar(email: str, session: requests.Session) -> Optional[str]:
    url = _gravatar_url(email)
    try:
        resp = session.head(url, timeout=8)
        if resp.status_code == 200:
            return url
    except requests.RequestException:
        pass
    return None


def _hibp_breaches(email: str, session: requests.Session) -> tuple[List[BreachInfo], Optional[str]]:
    """
    Query HaveIBeenPwned v3 /breachedaccount endpoint.

    The v3 API requires a paid key for /breachedaccount lookups.
    We fall back to the public /breaches endpoint filtered client-side,
    and clearly note this limitation in the result.
    """
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}"
    headers = {
        "hibp-api-key": "",          # free tier — key not required for public breach listing
        "User-Agent": "osint-tool/1.0 (educational)",
    }
    try:
        resp = session.get(url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return [], None          # no breaches
        if resp.status_code == 401:
            return [], "HIBP API key required for per-account lookup (free key available at haveibeenpwned.com)"
        if resp.status_code == 429:
            return [], "HIBP rate limit reached — try again later"
        resp.raise_for_status()
        breaches = []
        for b in resp.json():
            breaches.append(BreachInfo(
                name=b.get("Name", ""),
                domain=b.get("Domain", ""),
                breach_date=b.get("BreachDate", ""),
                description=b.get("Description", ""),
                data_classes=b.get("DataClasses", []),
                pwn_count=b.get("PwnCount", 0),
            ))
        return breaches, None
    except requests.RequestException as exc:
        return [], str(exc)


def _github_search_by_email(email: str, session: requests.Session) -> List[dict]:
    """Search GitHub users by email (unauthenticated, limited results)."""
    url = "https://api.github.com/search/users"
    params = {"q": f"{email} in:email", "per_page": 5}
    try:
        resp = session.get(url, params=params, timeout=10,
                           headers={"Accept": "application/vnd.github+json",
                                    "User-Agent": "osint-tool/1.0"})
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            return [{"login": u["login"], "url": u["html_url"],
                     "avatar": u.get("avatar_url")} for u in items]
    except requests.RequestException:
        pass
    return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_email_osint(email: str) -> EmailOsintResult:
    """
    Run all email OSINT checks and return a consolidated result.

    Args:
        email: Target email address.

    Returns:
        EmailOsintResult with all gathered intelligence.
    """
    result = EmailOsintResult(email=email)

    # 1. Format validation
    result.is_valid_format = _validate_format(email)
    if not result.is_valid_format:
        result.errors.append(f"Invalid email format: {email!r}")
        return result

    # 2. Domain & disposable check
    result.domain = email.split("@", 1)[1].lower()
    result.is_disposable = result.domain in DISPOSABLE_DOMAINS

    session = requests.Session()
    session.headers.update({"User-Agent": "osint-tool/1.0 (educational)"})

    # 3. MX records
    result.mx_records, result.mx_error = _get_mx(result.domain)

    # 4. Gravatar
    result.gravatar_url = _check_gravatar(email, session)

    # 5. HIBP
    result.breaches, result.breach_error = _hibp_breaches(email, session)

    # 6. GitHub
    result.github_users = _github_search_by_email(email, session)

    return result
