"""
Tests for the phone_lookup module.
"""

import pytest
from osint_tool.modules.phone_lookup import run_phone_lookup


class TestPhoneLookup:
    def test_valid_us_number(self):
        result = run_phone_lookup("+14155552671")
        assert result.is_valid is True
        assert result.country_code == "1"
        assert "US" in (result.country or "") or "San Francisco" in (result.country or "")

    def test_invalid_number(self):
        result = run_phone_lookup("+00000000000")
        assert result.is_valid is False

    def test_international_format_present(self):
        result = run_phone_lookup("+14155552671")
        assert result.international_format is not None
        assert "+" in result.international_format

    def test_line_type_present(self):
        result = run_phone_lookup("+14155552671")
        assert result.line_type is not None
        assert result.line_type in (
            "FIXED_LINE", "MOBILE", "FIXED_LINE_OR_MOBILE",
            "TOLL_FREE", "PREMIUM_RATE", "VOIP", "UNKNOWN",
        )

    def test_uk_number(self):
        result = run_phone_lookup("+447911123456")
        assert result.is_valid is True

    def test_to_dict_contains_required_keys(self):
        result = run_phone_lookup("+14155552671")
        d = result.to_dict()
        for key in ("phone", "is_valid", "country", "line_type", "carrier", "timezones"):
            assert key in d, f"Missing key: {key}"

    def test_malformed_number_no_crash(self):
        result = run_phone_lookup("not-a-phone-number")
        assert result.is_valid is False
        # Should not raise
        _ = result.to_dict()
