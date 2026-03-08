"""
report.py — Report generation utilities.

Supports:
  - JSON output
  - Plain-text (console-friendly) output
  - Styled HTML output (self-contained, no external CDN)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from jinja2 import Environment, BaseLoader

# ---------------------------------------------------------------------------
# HTML template (inline Jinja2)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report — {{ target }}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 1.5rem 2rem; }
  header h1 { color: #58a6ff; font-size: 1.6rem; }
  header p  { color: #8b949e; font-size: .85rem; margin-top: .25rem; }
  main { max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }
  section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }
  section > h2 { padding: .75rem 1.25rem; font-size: 1rem; font-weight: 600;
                 background: #21262d; color: #58a6ff; border-bottom: 1px solid #30363d; }
  table { width: 100%; border-collapse: collapse; font-size: .85rem; }
  th { background: #21262d; color: #8b949e; text-align: left; padding: .5rem .75rem;
       border-bottom: 1px solid #30363d; font-weight: 600; }
  td { padding: .45rem .75rem; border-bottom: 1px solid #21262d; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .badge { display: inline-block; padding: .15rem .5rem; border-radius: 4px;
            font-size: .75rem; font-weight: 700; }
  .badge-green  { background: #1a472a; color: #56d364; }
  .badge-red    { background: #4d1b1e; color: #f85149; }
  .badge-yellow { background: #3d2d00; color: #d29922; }
  .badge-blue   { background: #0d2149; color: #58a6ff; }
  .mono { font-family: monospace; font-size: .82rem; }
  .snippet { color: #8b949e; font-size: .78rem; max-width: 420px; overflow: hidden;
             text-overflow: ellipsis; white-space: nowrap; }
  .empty { color: #6e7681; padding: .75rem 1.25rem; font-style: italic; font-size: .875rem; }
</style>
</head>
<body>
<header>
  <h1>🔍 OSINT Intelligence Report</h1>
  <p>Target: <strong>{{ target }}</strong> &nbsp;|&nbsp; Generated: {{ generated_at }}</p>
</header>
<main>

{% if data.dork_search %}
<section>
  <h2>🕵️ Dork Search Results ({{ data.dork_search.results | length }})</h2>
  {% if data.dork_search.results %}
  <table>
    <tr><th>Engine</th><th>Title</th><th>URL</th><th>Snippet</th></tr>
    {% for r in data.dork_search.results %}
    <tr>
      <td><span class="badge badge-blue">{{ r.engine }}</span></td>
      <td>{{ r.title }}</td>
      <td><a href="{{ r.url }}" target="_blank" class="mono">{{ r.url[:80] }}{% if r.url|length > 80 %}…{% endif %}</a></td>
      <td class="snippet">{{ r.snippet }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="empty">No results found.</p>
  {% endif %}
</section>
{% endif %}

{% if data.email_osint %}
{% set e = data.email_osint %}
<section>
  <h2>📧 Email OSINT — {{ e.email }}</h2>
  <table>
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Valid format</td><td>{% if e.is_valid_format %}<span class="badge badge-green">Yes</span>{% else %}<span class="badge badge-red">No</span>{% endif %}</td></tr>
    <tr><td>Disposable</td><td>{% if e.is_disposable %}<span class="badge badge-red">Yes</span>{% else %}<span class="badge badge-green">No</span>{% endif %}</td></tr>
    <tr><td>Domain</td><td>{{ e.domain }}</td></tr>
    <tr><td>MX Records</td><td class="mono">{{ e.mx_records | join(', ') or '—' }}</td></tr>
    <tr><td>Gravatar</td><td>{% if e.gravatar_url %}<a href="{{ e.gravatar_url }}" target="_blank">{{ e.gravatar_url }}</a>{% else %}—{% endif %}</td></tr>
    <tr><td>Breaches</td><td>
      {% if e.breaches %}
        {% for b in e.breaches %}
          <span class="badge badge-red">{{ b.name }}</span>&nbsp;
        {% endfor %}
      {% else %}<span class="badge badge-green">None found</span>{% endif %}
    </td></tr>
  </table>
</section>
{% endif %}

{% if data.username_search %}
{% set u = data.username_search %}
<section>
  <h2>👤 Username Enumeration — @{{ u.username }} ({{ u.found | length }} found)</h2>
  {% if u.found %}
  <table>
    <tr><th>Platform</th><th>URL</th></tr>
    {% for r in u.found %}
    <tr>
      <td>{{ r.platform }}</td>
      <td><a href="{{ r.url }}" target="_blank">{{ r.url }}</a></td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="empty">Username not found on any checked platform.</p>
  {% endif %}
</section>
{% endif %}

{% if data.phone_lookup %}
{% set p = data.phone_lookup %}
<section>
  <h2>📞 Phone Lookup — {{ p.phone }}</h2>
  <table>
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Valid</td><td>{% if p.is_valid %}<span class="badge badge-green">Yes</span>{% else %}<span class="badge badge-red">No</span>{% endif %}</td></tr>
    <tr><td>International format</td><td class="mono">{{ p.international_format or '—' }}</td></tr>
    <tr><td>Country</td><td>{{ p.country or '—' }}</td></tr>
    <tr><td>Region</td><td>{{ p.region or '—' }}</td></tr>
    <tr><td>Carrier</td><td>{{ p.carrier or '—' }}</td></tr>
    <tr><td>Line type</td><td>{{ p.line_type or '—' }}</td></tr>
    <tr><td>Timezones</td><td>{{ p.timezones | join(', ') or '—' }}</td></tr>
  </table>
</section>
{% endif %}

{% if data.domain_osint %}
{% set d = data.domain_osint %}
<section>
  <h2>🌐 Domain OSINT — {{ d.domain }}</h2>
  {% if d.whois %}
  <table>
    <tr><th>WHOIS Property</th><th>Value</th></tr>
    <tr><td>Registrar</td><td>{{ d.whois.registrar or '—' }}</td></tr>
    <tr><td>Created</td><td>{{ d.whois.creation_date or '—' }}</td></tr>
    <tr><td>Expires</td><td>{{ d.whois.expiration_date or '—' }}</td></tr>
    <tr><td>Registrant org</td><td>{{ d.whois.registrant_org or '—' }}</td></tr>
    <tr><td>Registrant country</td><td>{{ d.whois.registrant_country or '—' }}</td></tr>
    <tr><td>Name servers</td><td class="mono">{{ d.whois.name_servers | join(', ') or '—' }}</td></tr>
  </table>
  {% endif %}
  {% if d.dns %}
  <table style="margin-top:.5rem">
    <tr><th>DNS Type</th><th>Values</th></tr>
    {% for rtype in ('A','AAAA','MX','NS','TXT','CNAME') %}
    {% set vals = d.dns[rtype] if d.dns[rtype] is defined else [] %}
    {% if vals %}
    <tr><td class="badge badge-blue">{{ rtype }}</td><td class="mono">{{ vals | join('<br>') }}</td></tr>
    {% endif %}
    {% endfor %}
  </table>
  {% endif %}
  {% if d.subdomains %}
  <p style="padding:.5rem 1rem; color:#8b949e; font-size:.8rem;">
    {{ d.subdomains | length }} subdomains found via certificate transparency (crt.sh)
  </p>
  {% endif %}
</section>
{% endif %}

{% if data.paste_search %}
{% set ps = data.paste_search %}
<section>
  <h2>📋 Paste Site Results — "{{ ps.query }}" ({{ ps.entries | length }})</h2>
  {% if ps.entries %}
  <table>
    <tr><th>Source</th><th>Title</th><th>URL</th><th>Date</th></tr>
    {% for e in ps.entries %}
    <tr>
      <td><span class="badge badge-yellow">{{ e.source }}</span></td>
      <td>{{ e.title }}</td>
      <td><a href="{{ e.url }}" target="_blank" class="mono">{{ e.url }}</a></td>
      <td>{{ e.date or '—' }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="empty">No results found.</p>
  {% endif %}
</section>
{% endif %}

</main>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_json_report(data: Dict[str, Any], target: str, output_path: Optional[str] = None) -> str:
    """
    Serialize gathered OSINT data to JSON.

    Args:
        data: Dict of module_name → result.to_dict() mappings.
        target: Human-readable target description.
        output_path: If given, write to this file path.

    Returns:
        JSON string.
    """
    payload = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    text = json.dumps(payload, indent=2, default=str)
    if output_path:
        _write(output_path, text)
    return text


def generate_text_report(data: Dict[str, Any], target: str, output_path: Optional[str] = None) -> str:
    """Generate a plain-text report."""
    lines = [
        "=" * 70,
        f"  OSINT INTELLIGENCE REPORT",
        f"  Target  : {target}",
        f"  Created : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "=" * 70,
        "",
    ]

    _section_dork_search(data, lines)
    _section_email_osint(data, lines)
    _section_username(data, lines)
    _section_phone(data, lines)
    _section_domain(data, lines)
    _section_paste(data, lines)

    text = "\n".join(lines)
    if output_path:
        _write(output_path, text)
    return text


def generate_html_report(data: Dict[str, Any], target: str, output_path: Optional[str] = None) -> str:
    """Generate a self-contained styled HTML report."""
    env = Environment(loader=BaseLoader())
    tpl = env.from_string(_HTML_TEMPLATE)
    html = tpl.render(
        target=target,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        data=data,
    )
    if output_path:
        _write(output_path, html)
    return html


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _section_dork_search(data: dict, lines: list) -> None:
    d = data.get("dork_search")
    if not d:
        return
    results = d.get("results", [])
    lines.append(f"[DORK SEARCH] {len(results)} results")
    lines.append("-" * 70)
    for r in results[:50]:  # cap display at 50
        lines.append(f"  [{r.get('engine','?')}] {r.get('title','')}")
        lines.append(f"        {r.get('url','')}")
        snippet = r.get("snippet", "")
        if snippet:
            lines.append(f"        {snippet[:120]}")
    lines.append("")


def _section_email_osint(data: dict, lines: list) -> None:
    d = data.get("email_osint")
    if not d:
        return
    lines.append(f"[EMAIL OSINT] {d.get('email')}")
    lines.append("-" * 70)
    lines.append(f"  Valid format : {d.get('is_valid_format')}")
    lines.append(f"  Disposable   : {d.get('is_disposable')}")
    lines.append(f"  Domain       : {d.get('domain')}")
    lines.append(f"  MX records   : {', '.join(d.get('mx_records', [])) or 'none'}")
    lines.append(f"  Gravatar     : {d.get('gravatar_url') or 'none'}")
    breaches = d.get("breaches", [])
    if breaches:
        lines.append(f"  ⚠ BREACHES ({len(breaches)}):")
        for b in breaches:
            lines.append(f"    - {b.get('name')} [{b.get('breach_date')}] "
                         f"pwn_count={b.get('pwn_count')}")
    else:
        lines.append("  No breaches found.")
    lines.append("")


def _section_username(data: dict, lines: list) -> None:
    d = data.get("username_search")
    if not d:
        return
    found = d.get("found", [])
    lines.append(f"[USERNAME ENUMERATION] @{d.get('username')} — {len(found)} platforms found")
    lines.append("-" * 70)
    for r in found:
        lines.append(f"  ✓ {r.get('platform'):<25} {r.get('url')}")
    lines.append("")


def _section_phone(data: dict, lines: list) -> None:
    d = data.get("phone_lookup")
    if not d:
        return
    lines.append(f"[PHONE LOOKUP] {d.get('phone')}")
    lines.append("-" * 70)
    for key in ("is_valid", "international_format", "country", "region", "carrier", "line_type"):
        lines.append(f"  {key:<20} : {d.get(key)}")
    tz = d.get("timezones", [])
    if tz:
        lines.append(f"  {'timezones':<20} : {', '.join(tz)}")
    lines.append("")


def _section_domain(data: dict, lines: list) -> None:
    d = data.get("domain_osint")
    if not d:
        return
    lines.append(f"[DOMAIN OSINT] {d.get('domain')}")
    lines.append("-" * 70)
    w = d.get("whois") or {}
    lines.append(f"  Registrar    : {w.get('registrar')}")
    lines.append(f"  Created      : {w.get('creation_date')}")
    lines.append(f"  Expires      : {w.get('expiration_date')}")
    dns_ = d.get("dns") or {}
    for rt in ("A", "MX", "NS"):
        vals = dns_.get(rt)
        if vals:
            lines.append(f"  {rt:<13}: {', '.join(vals)}")
    subs = d.get("subdomains", [])
    if subs:
        lines.append(f"  Subdomains   : {len(subs)} (via crt.sh)")
    lines.append("")


def _section_paste(data: dict, lines: list) -> None:
    d = data.get("paste_search")
    if not d:
        return
    entries = d.get("entries", [])
    lines.append(f"[PASTE SEARCH] \"{d.get('query')}\" — {len(entries)} results")
    lines.append("-" * 70)
    for e in entries:
        lines.append(f"  [{e.get('source')}] {e.get('title')}")
        lines.append(f"    {e.get('url')}")
    lines.append("")
