"""
Tests for the report generation utilities.
"""

import json
import os
import tempfile
import pytest

from osint_tool.utils.report import (
    generate_json_report,
    generate_text_report,
    generate_html_report,
)


_SAMPLE_DATA = {
    "phone_lookup": {
        "phone": "+14155552671",
        "is_valid": True,
        "international_format": "+1 415-555-2671",
        "country": "United States",
        "region": "California",
        "carrier": None,
        "line_type": "FIXED_LINE_OR_MOBILE",
        "timezones": ["America/Los_Angeles"],
        "errors": [],
    },
    "email_osint": {
        "email": "alice@example.com",
        "is_valid_format": True,
        "is_disposable": False,
        "domain": "example.com",
        "mx_records": ["mail.example.com"],
        "mx_error": None,
        "gravatar_url": None,
        "breaches": [],
        "breach_error": None,
        "github_users": [],
        "errors": [],
    },
}

_TARGET = "Alice Example"


class TestGenerateJsonReport:
    def test_returns_valid_json_string(self):
        out = generate_json_report(_SAMPLE_DATA, _TARGET)
        parsed = json.loads(out)
        assert parsed["target"] == _TARGET
        assert "data" in parsed
        assert "generated_at" in parsed

    def test_contains_phone_data(self):
        out = generate_json_report(_SAMPLE_DATA, _TARGET)
        parsed = json.loads(out)
        assert parsed["data"]["phone_lookup"]["is_valid"] is True

    def test_writes_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            generate_json_report(_SAMPLE_DATA, _TARGET, path)
            assert os.path.exists(path)
            with open(path) as f:
                parsed = json.loads(f.read())
            assert parsed["target"] == _TARGET


class TestGenerateTextReport:
    def test_returns_string(self):
        out = generate_text_report(_SAMPLE_DATA, _TARGET)
        assert isinstance(out, str)
        assert len(out) > 100

    def test_contains_target(self):
        out = generate_text_report(_SAMPLE_DATA, _TARGET)
        assert _TARGET in out

    def test_contains_phone_section(self):
        out = generate_text_report(_SAMPLE_DATA, _TARGET)
        assert "PHONE LOOKUP" in out

    def test_contains_email_section(self):
        out = generate_text_report(_SAMPLE_DATA, _TARGET)
        assert "EMAIL OSINT" in out

    def test_writes_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.txt")
            generate_text_report(_SAMPLE_DATA, _TARGET, path)
            assert os.path.exists(path)


class TestGenerateHtmlReport:
    def test_returns_string(self):
        out = generate_html_report(_SAMPLE_DATA, _TARGET)
        assert isinstance(out, str)

    def test_contains_html_structure(self):
        out = generate_html_report(_SAMPLE_DATA, _TARGET)
        assert "<!DOCTYPE html>" in out
        assert "<html" in out

    def test_contains_target_in_title(self):
        out = generate_html_report(_SAMPLE_DATA, _TARGET)
        assert _TARGET in out

    def test_writes_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.html")
            generate_html_report(_SAMPLE_DATA, _TARGET, path)
            assert os.path.exists(path)
            with open(path) as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content


class TestEdgeCases:
    def test_empty_data_no_crash(self):
        out = generate_text_report({}, "Empty Target")
        assert isinstance(out, str)

    def test_json_with_nested_objects(self):
        data = {
            "dork_search": {
                "name": "Test",
                "results": [{"engine": "Google", "dork": '"Test"',
                              "url": "https://example.com", "title": "Test", "snippet": ""}],
                "errors": [],
            }
        }
        out = generate_json_report(data, "Test")
        parsed = json.loads(out)
        assert len(parsed["data"]["dork_search"]["results"]) == 1
