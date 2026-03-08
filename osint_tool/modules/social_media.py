"""
social_media.py — Username enumeration across 50+ social / professional platforms.

Uses only free, unauthenticated HTTP checks.  Each platform entry defines how
to detect whether a profile page exists (HTTP 200 + optional content probe).
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform registry
# ---------------------------------------------------------------------------
# Each entry:
#   url_template  : profile URL with {username} placeholder
#   check_type    : "status_200" | "content_probe"
#   probe_string  : (for content_probe) string that must appear in the page
#   not_found_str : string that indicates the profile does NOT exist (overrides 200)

PLATFORMS: List[dict] = [
    # ---------- General social ----------
    {"name": "Twitter/X",      "url": "https://x.com/{username}",
     "check": "status_200", "not_found": "This account doesn't exist"},
    {"name": "Instagram",      "url": "https://www.instagram.com/{username}/",
     "check": "status_200", "not_found": "Sorry, this page isn't available"},
    {"name": "Facebook",       "url": "https://www.facebook.com/{username}",
     "check": "status_200", "not_found": "The link you followed may have expired"},
    {"name": "TikTok",         "url": "https://www.tiktok.com/@{username}",
     "check": "status_200", "not_found": "Couldn't find this account"},
    {"name": "Snapchat",       "url": "https://www.snapchat.com/add/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Pinterest",      "url": "https://www.pinterest.com/{username}/",
     "check": "status_200", "not_found": "Sorry! We couldn't find that page"},
    {"name": "Tumblr",         "url": "https://{username}.tumblr.com/",
     "check": "status_200", "not_found": "There's nothing here"},
    # ---------- Professional ----------
    {"name": "LinkedIn",       "url": "https://www.linkedin.com/in/{username}",
     "check": "status_200", "not_found": "Page not found"},
    {"name": "GitHub",         "url": "https://github.com/{username}",
     "check": "status_200", "not_found": "Not Found"},
    {"name": "GitLab",         "url": "https://gitlab.com/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Bitbucket",      "url": "https://bitbucket.org/{username}/",
     "check": "status_200", "not_found": ""},
    {"name": "Stack Overflow", "url": "https://stackoverflow.com/users/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Keybase",        "url": "https://keybase.io/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "AngelList",      "url": "https://angel.co/{username}",
     "check": "status_200", "not_found": ""},
    # ---------- Dev / creative ----------
    {"name": "Dev.to",         "url": "https://dev.to/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Hashnode",       "url": "https://hashnode.com/@{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Medium",         "url": "https://medium.com/@{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Codepen",        "url": "https://codepen.io/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Dribbble",       "url": "https://dribbble.com/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Behance",        "url": "https://www.behance.net/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "HackerNews",     "url": "https://news.ycombinator.com/user?id={username}",
     "check": "content_probe", "probe": "created:", "not_found": "No such user"},
    # ---------- Video / streaming ----------
    {"name": "YouTube",        "url": "https://www.youtube.com/@{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Twitch",         "url": "https://www.twitch.tv/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Vimeo",          "url": "https://vimeo.com/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "DailyMotion",    "url": "https://www.dailymotion.com/{username}",
     "check": "status_200", "not_found": ""},
    # ---------- Forums / community ----------
    {"name": "Reddit",         "url": "https://www.reddit.com/user/{username}",
     "check": "status_200", "not_found": "Sorry, nobody on Reddit goes by that name"},
    {"name": "Quora",          "url": "https://www.quora.com/profile/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Disqus",         "url": "https://disqus.com/by/{username}/",
     "check": "status_200", "not_found": ""},
    {"name": "ProductHunt",    "url": "https://www.producthunt.com/@{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Steam",          "url": "https://steamcommunity.com/id/{username}",
     "check": "content_probe", "probe": "persona_name", "not_found": "The specified profile could not be found"},
    {"name": "Xbox Gamertag",  "url": "https://account.xbox.com/en-US/Profile?gamertag={username}",
     "check": "status_200", "not_found": ""},
    # ---------- Blogging / portfolio ----------
    {"name": "Wordpress",      "url": "https://{username}.wordpress.com/",
     "check": "status_200", "not_found": "doesn't exist"},
    {"name": "Blogger",        "url": "https://{username}.blogspot.com/",
     "check": "status_200", "not_found": "Blog not found"},
    {"name": "About.me",       "url": "https://about.me/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Linktree",       "url": "https://linktr.ee/{username}",
     "check": "status_200", "not_found": ""},
    # ---------- Music ----------
    {"name": "SoundCloud",     "url": "https://soundcloud.com/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Last.fm",        "url": "https://www.last.fm/user/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Spotify",        "url": "https://open.spotify.com/user/{username}",
     "check": "status_200", "not_found": ""},
    # ---------- Photo ----------
    {"name": "Flickr",         "url": "https://www.flickr.com/people/{username}/",
     "check": "status_200", "not_found": ""},
    {"name": "500px",          "url": "https://500px.com/p/{username}",
     "check": "status_200", "not_found": ""},
    # ---------- Q&A / academic ----------
    {"name": "ResearchGate",   "url": "https://www.researchgate.net/profile/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Academia.edu",   "url": "https://independent.academia.edu/{username}",
     "check": "status_200", "not_found": ""},
    # ---------- Other ----------
    {"name": "Gravatar",       "url": "https://en.gravatar.com/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Patreon",        "url": "https://www.patreon.com/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Ko-fi",          "url": "https://ko-fi.com/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Buy Me a Coffee","url": "https://www.buymeacoffee.com/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Telegram",       "url": "https://t.me/{username}",
     "check": "status_200", "not_found": ""},
    {"name": "Signal",         "url": "https://signal.group/#ckkj_{username}",
     "check": "status_200", "not_found": ""},
    {"name": "DockerHub",      "url": "https://hub.docker.com/u/{username}/",
     "check": "status_200", "not_found": ""},
    {"name": "npm",            "url": "https://www.npmjs.com/~{username}",
     "check": "status_200", "not_found": ""},
    {"name": "PyPI",           "url": "https://pypi.org/user/{username}/",
     "check": "status_200", "not_found": ""},
]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PlatformResult:
    platform: str
    url: str
    found: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


@dataclass
class UsernameSearchResult:
    username: str
    found: List[PlatformResult] = field(default_factory=list)
    not_found: List[PlatformResult] = field(default_factory=list)
    errors: List[PlatformResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "found": [vars(r) for r in self.found],
            "not_found_count": len(self.not_found),
            "errors": [vars(r) for r in self.errors],
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_platform(username: str, platform: dict, timeout: int = 10) -> PlatformResult:
    url = platform["url"].format(username=username)
    not_found_str = platform.get("not_found", "")
    check = platform.get("check", "status_200")
    probe = platform.get("probe", "")

    try:
        resp = requests.get(
            url,
            headers={"User-Agent": _USER_AGENTS[0]},
            timeout=timeout,
            allow_redirects=True,
        )
        if resp.status_code == 404:
            return PlatformResult(platform["name"], url, False, resp.status_code)

        body = resp.text
        if not_found_str and not_found_str in body:
            return PlatformResult(platform["name"], url, False, resp.status_code)

        if check == "content_probe":
            found = probe and probe in body
        else:
            found = resp.status_code == 200

        return PlatformResult(platform["name"], url, found, resp.status_code)

    except requests.RequestException as exc:
        return PlatformResult(platform["name"], url, False, None, str(exc))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_username(
    username: str,
    platforms: Optional[List[dict]] = None,
    max_workers: int = 20,
    timeout: int = 10,
) -> UsernameSearchResult:
    """
    Check a username across all (or a specified subset of) platforms concurrently.

    Args:
        username: The handle to search for.
        platforms: Override the default PLATFORMS list.
        max_workers: Thread pool size.
        timeout: HTTP request timeout (seconds).

    Returns:
        UsernameSearchResult with found / not_found / errors grouped.
    """
    platform_list = platforms or PLATFORMS
    result = UsernameSearchResult(username=username)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check_platform, username, p, timeout): p for p in platform_list}
        for future in as_completed(futures):
            pr = future.result()
            if pr.error:
                result.errors.append(pr)
            elif pr.found:
                result.found.append(pr)
            else:
                result.not_found.append(pr)

    result.found.sort(key=lambda r: r.platform)
    result.not_found.sort(key=lambda r: r.platform)
    return result
