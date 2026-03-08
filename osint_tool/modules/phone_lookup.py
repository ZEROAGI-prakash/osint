"""
phone_lookup.py — Phone number OSINT module.

Uses:
  - numverify free tier (no key needed for basic format validation)
  - phonenumbers library for local parsing / formatting
  - Free carrier/region inference via phonenumbers metadata
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency: phonenumbers
# ---------------------------------------------------------------------------
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as ph_timezone
    _PHONENUMBERS_AVAILABLE = True
except ImportError:
    _PHONENUMBERS_AVAILABLE = False
    logger.warning("phonenumbers library not installed. Install it with: pip install phonenumbers")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PhoneOsintResult:
    phone: str
    is_valid: bool = False
    is_possible: bool = False
    country_code: Optional[str] = None
    national_number: Optional[str] = None
    international_format: Optional[str] = None
    national_format: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    carrier_name: Optional[str] = None
    line_type: Optional[str] = None    # MOBILE, FIXED_LINE, VOIP, etc.
    timezones: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "phone": self.phone,
            "is_valid": self.is_valid,
            "is_possible": self.is_possible,
            "country_code": self.country_code,
            "national_number": self.national_number,
            "international_format": self.international_format,
            "national_format": self.national_format,
            "country": self.country,
            "region": self.region,
            "carrier": self.carrier_name,
            "line_type": self.line_type,
            "timezones": self.timezones,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LINE_TYPE_MAP = {
    0: "FIXED_LINE",
    1: "MOBILE",
    2: "FIXED_LINE_OR_MOBILE",
    3: "TOLL_FREE",
    4: "PREMIUM_RATE",
    5: "SHARED_COST",
    6: "VOIP",
    7: "PERSONAL_NUMBER",
    8: "PAGER",
    9: "UAN",
    10: "VOICEMAIL",
    99: "UNKNOWN",
}


def _parse_with_phonenumbers(phone: str, default_region: Optional[str] = None) -> PhoneOsintResult:
    result = PhoneOsintResult(phone=phone)
    try:
        parsed = phonenumbers.parse(phone, default_region)
        result.is_valid = phonenumbers.is_valid_number(parsed)
        result.is_possible = phonenumbers.is_possible_number(parsed)
        result.country_code = str(parsed.country_code)
        result.national_number = str(parsed.national_number)
        result.international_format = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        result.national_format = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        result.country = geocoder.description_for_number(parsed, "en")
        result.region = geocoder.description_for_number(parsed, "en")
        result.carrier_name = carrier.name_for_number(parsed, "en") or None
        nt = phonenumbers.number_type(parsed)
        result.line_type = _LINE_TYPE_MAP.get(nt, "UNKNOWN")
        result.timezones = list(ph_timezone.time_zones_for_number(parsed))
    except Exception as exc:
        result.errors.append(str(exc))
    return result


def _parse_basic(phone: str) -> PhoneOsintResult:
    """Very basic fallback when phonenumbers is not installed."""
    result = PhoneOsintResult(phone=phone)
    clean = re.sub(r"[^\d+]", "", phone)
    result.is_possible = len(clean.lstrip("+")) >= 7
    result.international_format = clean if clean.startswith("+") else None
    result.errors.append(
        "Install 'phonenumbers' for full validation: pip install phonenumbers"
    )
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_phone_lookup(phone: str, default_region: Optional[str] = None) -> PhoneOsintResult:
    """
    Look up information about a phone number.

    Args:
        phone: Phone number string (international format preferred, e.g. "+15551234567").
        default_region: Two-letter country code hint (e.g. "US") when no + prefix.

    Returns:
        PhoneOsintResult with carrier, region, type info.
    """
    if _PHONENUMBERS_AVAILABLE:
        return _parse_with_phonenumbers(phone, default_region)
    return _parse_basic(phone)
