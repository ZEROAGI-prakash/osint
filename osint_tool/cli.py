"""
cli.py — Command-line interface for the OSINT tool.

Sub-commands:
  person   — person-centric OSINT (dorks + social + paste)
  email    — email OSINT (breach, MX, gravatar, GitHub)
  username — username enumeration across 50+ platforms
  phone    — phone number lookup
  domain   — domain WHOIS, DNS, subdomains
  dorks    — print dork URLs for manual browser investigation

Usage:
  osint person   --name "John Doe" [--email ...] [--username ...] [--phone ...]
  osint email    --email john@example.com
  osint username --username johndoe
  osint phone    --phone "+15551234567"
  osint domain   --domain example.com
  osint dorks    --name "John Doe" [--email ...] [--gov-only]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Optional

from colorama import Fore, Style, init as colorama_init

from osint_tool.modules.dork_search import run_dork_search, build_dork_urls
from osint_tool.modules.email_osint import run_email_osint
from osint_tool.modules.social_media import check_username
from osint_tool.modules.phone_lookup import run_phone_lookup
from osint_tool.modules.whois_dns import run_domain_osint
from osint_tool.modules.paste_search import run_paste_search
from osint_tool.utils.report import generate_json_report, generate_text_report, generate_html_report

colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("osint_tool")


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

def _banner() -> None:
    print(Fore.CYAN + r"""
  ___  ____ ___ _   _ _____   _____ ___   ___  _
 / _ \/ ___|_ _| \ | |_   _| |_   _/ _ \ / _ \| |
| | | \___ \| ||  \| | | |     | || | | | | | | |
| |_| |___) | || |\  | | |     | || |_| | |_| | |___
 \___/|____/___|_| \_| |_|     |_| \___/ \___/|_____|
  Professional Free-Services OSINT Framework  v1.0
""" + Style.RESET_ALL)


def _ok(msg: str) -> None:
    print(Fore.GREEN + f"  [+] {msg}" + Style.RESET_ALL)


def _info(msg: str) -> None:
    print(Fore.BLUE + f"  [*] {msg}" + Style.RESET_ALL)


def _warn(msg: str) -> None:
    print(Fore.YELLOW + f"  [!] {msg}" + Style.RESET_ALL)


def _err(msg: str) -> None:
    print(Fore.RED + f"  [-] {msg}" + Style.RESET_ALL)


def _section(title: str) -> None:
    print()
    print(Fore.CYAN + "  " + "─" * 60)
    print(Fore.CYAN + f"  {title}")
    print(Fore.CYAN + "  " + "─" * 60 + Style.RESET_ALL)


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------

def _cmd_person(args: argparse.Namespace) -> dict:
    """Run person-centric OSINT: dorks + social + paste."""
    results: dict = {}
    target_parts = []
    if args.name:
        target_parts.append(args.name)
    if args.email:
        target_parts.append(args.email)
    target = " / ".join(target_parts) or "unknown"

    # --- Dork search ---
    _section("DORK SEARCH")
    _info(f"Running dork search for {target!r} …")
    dork_result = run_dork_search(
        name=args.name,
        email=args.email,
        username=args.username,
        phone=args.phone,
        use_gov_dorks=True,
        use_social_dorks=True,
        use_leak_dorks=True,
        engine=args.engine,
        delay=args.delay,
    )
    results["dork_search"] = dork_result.to_dict()
    _ok(f"{len(dork_result.results)} dork hits found")
    for r in dork_result.results[:15]:
        print(f"    [{r.engine}] {r.title}")
        print(f"         {Fore.BLUE}{r.url}{Style.RESET_ALL}")
    if len(dork_result.results) > 15:
        _info(f"… and {len(dork_result.results) - 15} more (see full report)")

    # --- Social media ---
    if args.username:
        _section("SOCIAL MEDIA ENUMERATION")
        _info(f"Checking @{args.username} across 50+ platforms …")
        sm_result = check_username(args.username)
        results["username_search"] = sm_result.to_dict()
        _ok(f"Found on {len(sm_result.found)} platforms")
        for r in sm_result.found:
            _ok(f"  {r.platform:<25} {r.url}")

    # --- Paste search ---
    if args.name:
        _section("PASTE SITE SEARCH")
        _info(f"Searching paste sites for {args.name!r} …")
        paste_result = run_paste_search(args.name)
        results["paste_search"] = paste_result.to_dict()
        if paste_result.entries:
            _warn(f"{len(paste_result.entries)} paste entries found!")
            for e in paste_result.entries:
                _warn(f"  [{e.source}] {e.url}")
        else:
            _ok("No paste results found")

    # --- Email OSINT (if email provided) ---
    if args.email:
        _section("EMAIL OSINT")
        _info(f"Analysing {args.email!r} …")
        email_result = run_email_osint(args.email)
        results["email_osint"] = email_result.to_dict()
        _ok(f"Domain: {email_result.domain}  MX: {', '.join(email_result.mx_records) or 'none'}")
        if email_result.is_disposable:
            _warn("Disposable email domain!")
        if email_result.breaches:
            _warn(f"{len(email_result.breaches)} data breaches found!")
            for b in email_result.breaches:
                _warn(f"  {b.name} [{b.breach_date}]")
        else:
            _ok("No data breaches found")

    return results


def _cmd_email(args: argparse.Namespace) -> dict:
    _section(f"EMAIL OSINT — {args.email}")
    _info("Running email OSINT …")
    result = run_email_osint(args.email)
    _ok(f"Valid format     : {result.is_valid_format}")
    _ok(f"Domain           : {result.domain}")
    if result.is_disposable:
        _warn("Disposable domain!")
    _ok(f"MX records       : {', '.join(result.mx_records) or 'none'}")
    _ok(f"Gravatar         : {result.gravatar_url or 'none'}")
    if result.breaches:
        _warn(f"{len(result.breaches)} BREACH(ES) FOUND:")
        for b in result.breaches:
            _warn(f"  • {b.name} ({b.breach_date}) — {b.pwn_count:,} accounts")
    else:
        _ok("No data breaches found (HIBP)")
    if result.github_users:
        _ok(f"GitHub user(s): {', '.join(u['login'] for u in result.github_users)}")
    if result.breach_error:
        _warn(f"Breach check note: {result.breach_error}")
    return {"email_osint": result.to_dict()}


def _cmd_username(args: argparse.Namespace) -> dict:
    _section(f"USERNAME ENUMERATION — @{args.username}")
    _info(f"Checking {args.username!r} across platforms …")
    result = check_username(args.username)
    _ok(f"Found on {len(result.found)} platform(s):")
    for r in result.found:
        print(f"    {Fore.GREEN}✓{Style.RESET_ALL}  {r.platform:<25}  {r.url}")
    if result.errors:
        _warn(f"{len(result.errors)} platform(s) returned errors (timeouts, etc.)")
    return {"username_search": result.to_dict()}


def _cmd_phone(args: argparse.Namespace) -> dict:
    _section(f"PHONE LOOKUP — {args.phone}")
    result = run_phone_lookup(args.phone, default_region=args.region)
    _ok(f"Valid            : {result.is_valid}")
    _ok(f"International    : {result.international_format or '—'}")
    _ok(f"Country          : {result.country or '—'}")
    _ok(f"Region           : {result.region or '—'}")
    _ok(f"Carrier          : {result.carrier_name or '—'}")
    _ok(f"Line type        : {result.line_type or '—'}")
    if result.timezones:
        _ok(f"Timezones        : {', '.join(result.timezones)}")
    return {"phone_lookup": result.to_dict()}


def _cmd_domain(args: argparse.Namespace) -> dict:
    _section(f"DOMAIN OSINT — {args.domain}")
    _info("Running WHOIS, DNS, certificate transparency …")
    result = run_domain_osint(args.domain, enumerate_subdomains=not args.no_subdomains)

    if result.whois and not result.whois.error:
        w = result.whois
        _ok(f"Registrar        : {w.registrar or '—'}")
        _ok(f"Created          : {w.creation_date or '—'}")
        _ok(f"Expires          : {w.expiration_date or '—'}")
        _ok(f"Registrant org   : {w.registrant_org or '—'}")
        _ok(f"Registrant country: {w.registrant_country or '—'}")
    elif result.whois and result.whois.error:
        _warn(f"WHOIS error: {result.whois.error}")

    if result.dns:
        d = result.dns
        if d.A:
            _ok(f"A records        : {', '.join(d.A)}")
        if d.MX:
            _ok(f"MX records       : {', '.join(d.MX)}")
        if d.NS:
            _ok(f"NS records       : {', '.join(d.NS)}")

    if result.ip_geo:
        for geo in result.ip_geo:
            _ok(f"IP {geo.ip:<15}: {geo.city}, {geo.country} ({geo.isp})")

    if result.subdomains:
        _ok(f"Subdomains       : {len(result.subdomains)} (via crt.sh)")
        for s in result.subdomains[:20]:
            print(f"    • {s.name}")
        if len(result.subdomains) > 20:
            _info(f"… and {len(result.subdomains) - 20} more (see full report)")

    return {"domain_osint": result.to_dict()}


def _cmd_dorks(args: argparse.Namespace) -> dict:
    """Print Google dork URLs for manual browser use."""
    _section("DORK URL GENERATOR")
    urls = build_dork_urls(
        name=args.name,
        email=args.email,
        username=args.username,
        phone=args.phone,
        gov_only=args.gov_only,
    )
    _ok(f"{len(urls)} dork URLs generated:")
    for u in urls:
        print(f"  {Fore.BLUE}{u}{Style.RESET_ALL}")
    return {}


# ---------------------------------------------------------------------------
# Report saving
# ---------------------------------------------------------------------------

def _save_reports(
    results: dict,
    target: str,
    output_dir: str,
    formats: list,
) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(" ", "_").replace("/", "-")[:40]
    prefix = os.path.join(output_dir, f"osint_{safe_target}_{ts}")
    os.makedirs(output_dir, exist_ok=True)

    if "json" in formats:
        path = f"{prefix}.json"
        generate_json_report(results, target, path)
        _ok(f"JSON report saved → {path}")

    if "txt" in formats:
        path = f"{prefix}.txt"
        generate_text_report(results, target, path)
        _ok(f"Text report saved → {path}")

    if "html" in formats:
        path = f"{prefix}.html"
        generate_html_report(results, target, path)
        _ok(f"HTML report saved → {path}")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint",
        description="Professional free-services OSINT tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output-dir", default="reports",
                        help="Directory to save reports (default: ./reports)")
    parser.add_argument("--format", dest="formats", default="json,html",
                        help="Comma-separated report formats: json, txt, html (default: json,html)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")

    sub = parser.add_subparsers(dest="command", required=True)

    # person
    p_person = sub.add_parser("person", help="Full person OSINT (dorks, social, paste)")
    p_person.add_argument("--name", help="Full name of the target", required=False)
    p_person.add_argument("--email", help="Target email address")
    p_person.add_argument("--username", help="Target username/handle")
    p_person.add_argument("--phone", help="Target phone number")
    p_person.add_argument("--engine", default="google", choices=["google", "bing", "both"],
                          help="Search engine for dorks (default: google)")
    p_person.add_argument("--delay", type=float, default=2.5,
                          help="Delay between dork requests in seconds (default: 2.5)")

    # email
    p_email = sub.add_parser("email", help="Email OSINT (breaches, MX, gravatar)")
    p_email.add_argument("--email", required=True, help="Target email address")

    # username
    p_uname = sub.add_parser("username", help="Username enumeration across 50+ platforms")
    p_uname.add_argument("--username", required=True, help="Target username/handle")

    # phone
    p_phone = sub.add_parser("phone", help="Phone number lookup")
    p_phone.add_argument("--phone", required=True, help="Phone number (e.g. +15551234567)")
    p_phone.add_argument("--region", default=None, help="Default region hint (e.g. US, IN, GB)")

    # domain
    p_domain = sub.add_parser("domain", help="Domain WHOIS, DNS, subdomains")
    p_domain.add_argument("--domain", required=True, help="Target domain (e.g. example.com)")
    p_domain.add_argument("--no-subdomains", action="store_true",
                          help="Skip certificate transparency subdomain enumeration")

    # dorks (print URLs only)
    p_dorks = sub.add_parser("dorks", help="Generate and print dork URLs for manual use")
    p_dorks.add_argument("--name", help="Target name")
    p_dorks.add_argument("--email", help="Target email")
    p_dorks.add_argument("--username", help="Target username")
    p_dorks.add_argument("--phone", help="Target phone")
    p_dorks.add_argument("--gov-only", action="store_true",
                         help="Include only government document dorks")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    _banner()

    # Dispatch
    command_map = {
        "person": _cmd_person,
        "email": _cmd_email,
        "username": _cmd_username,
        "phone": _cmd_phone,
        "domain": _cmd_domain,
        "dorks": _cmd_dorks,
    }
    handler = command_map.get(args.command)
    if not handler:
        parser.print_help()
        sys.exit(1)

    results = handler(args)

    # Build target string for report naming
    target_parts = []
    for attr in ("name", "email", "username", "phone", "domain"):
        val = getattr(args, attr, None)
        if val:
            target_parts.append(val)
    target = " / ".join(target_parts) or args.command

    # Save reports (skip for 'dorks' subcommand)
    if results and args.command != "dorks":
        formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
        _section("SAVING REPORTS")
        _save_reports(results, target, args.output_dir, formats)

    print()
    _ok("Done.")
    print()


if __name__ == "__main__":
    main()
