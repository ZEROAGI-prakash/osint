"""
whois_dns.py — WHOIS registration and DNS enumeration module.

Uses:
  - python-whois for domain registration data
  - dnspython for DNS record queries
  - crt.sh public API for certificate transparency / subdomain enumeration
  - ip-api.com for free IP geolocation
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import dns.resolver
import dns.reversename
import requests
import whois as python_whois

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class WhoisInfo:
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    registrant_name: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_email: Optional[str] = None
    status: List[str] = field(default_factory=list)
    raw: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DnsRecords:
    domain: str
    A: List[str] = field(default_factory=list)
    AAAA: List[str] = field(default_factory=list)
    MX: List[str] = field(default_factory=list)
    NS: List[str] = field(default_factory=list)
    TXT: List[str] = field(default_factory=list)
    CNAME: List[str] = field(default_factory=list)
    SOA: List[str] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)


@dataclass
class SubdomainEntry:
    name: str
    issuer: str
    not_before: str


@dataclass
class IpGeoInfo:
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    error: Optional[str] = None


@dataclass
class DomainOsintResult:
    domain: str
    whois: Optional[WhoisInfo] = None
    dns: Optional[DnsRecords] = None
    subdomains: List[SubdomainEntry] = field(default_factory=list)
    subdomain_error: Optional[str] = None
    ip_geo: List[IpGeoInfo] = field(default_factory=list)
    reverse_dns: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "whois": vars(self.whois) if self.whois else None,
            "dns": vars(self.dns) if self.dns else None,
            "subdomains": [vars(s) for s in self.subdomains],
            "subdomain_error": self.subdomain_error,
            "ip_geo": [vars(g) for g in self.ip_geo],
            "reverse_dns": self.reverse_dns,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_str(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    return str(val) if val is not None else None


def _get_whois(domain: str) -> WhoisInfo:
    info = WhoisInfo(domain=domain)
    try:
        w = python_whois.whois(domain)
        info.registrar = _safe_str(w.registrar)
        info.creation_date = _safe_str(w.creation_date)
        info.expiration_date = _safe_str(w.expiration_date)
        info.updated_date = _safe_str(w.updated_date)
        info.name_servers = [ns.lower() for ns in (w.name_servers or [])] if w.name_servers else []
        info.registrant_name = _safe_str(w.get("name"))
        info.registrant_org = _safe_str(w.org)
        info.registrant_country = _safe_str(w.country)
        info.registrant_email = _safe_str(w.emails)
        info.status = w.status if isinstance(w.status, list) else ([w.status] if w.status else [])
        info.raw = w.text
    except Exception as exc:
        info.error = str(exc)
    return info


def _get_dns_records(domain: str) -> DnsRecords:
    records = DnsRecords(domain=domain)
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            values = []
            for r in answers:
                values.append(str(r).rstrip("."))
            setattr(records, rtype, values)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception as exc:
            records.errors[rtype] = str(exc)
    return records


def _get_subdomains_crtsh(domain: str, session: requests.Session) -> tuple[List[SubdomainEntry], Optional[str]]:
    """Query crt.sh certificate transparency log for subdomains."""
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        resp = session.get(url, params=params, timeout=20,
                           headers={"User-Agent": "osint-tool/1.0"})
        resp.raise_for_status()
        seen: set = set()
        entries: List[SubdomainEntry] = []
        for entry in resp.json():
            name = entry.get("name_value", "").strip().lower()
            for n in name.split("\n"):
                n = n.strip().lstrip("*.")
                if n and n not in seen:
                    seen.add(n)
                    entries.append(SubdomainEntry(
                        name=n,
                        issuer=entry.get("issuer_name", ""),
                        not_before=entry.get("not_before", ""),
                    ))
        entries.sort(key=lambda e: e.name)
        return entries, None
    except requests.RequestException as exc:
        return [], str(exc)
    except Exception as exc:
        return [], str(exc)


def _geolocate_ip(ip: str, session: requests.Session) -> IpGeoInfo:
    geo = IpGeoInfo(ip=ip)
    try:
        resp = session.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,lat,lon",
                           timeout=8)
        data = resp.json()
        if data.get("status") == "success":
            geo.country = data.get("country")
            geo.country_code = data.get("countryCode")
            geo.region = data.get("regionName")
            geo.city = data.get("city")
            geo.isp = data.get("isp")
            geo.org = data.get("org")
            geo.lat = data.get("lat")
            geo.lon = data.get("lon")
        else:
            geo.error = data.get("message", "Unknown error")
    except Exception as exc:
        geo.error = str(exc)
    return geo


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_domain_osint(domain: str, enumerate_subdomains: bool = True) -> DomainOsintResult:
    """
    Run WHOIS, DNS, certificate transparency, and IP geo-location on a domain.

    Args:
        domain: Target domain (e.g. "example.com").
        enumerate_subdomains: Query crt.sh for subdomain enumeration.

    Returns:
        DomainOsintResult with all gathered intelligence.
    """
    result = DomainOsintResult(domain=domain)
    session = requests.Session()

    result.whois = _get_whois(domain)
    result.dns = _get_dns_records(domain)

    if enumerate_subdomains:
        result.subdomains, result.subdomain_error = _get_subdomains_crtsh(domain, session)

    # Geolocate A records
    for ip in result.dns.A:
        result.ip_geo.append(_geolocate_ip(ip, session))
        rdns = _reverse_dns(ip)
        if rdns:
            result.reverse_dns[ip] = rdns

    return result
