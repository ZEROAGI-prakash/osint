"""
Tests for the dork_search module.

These tests validate the dork template rendering and URL generation
without making live HTTP requests.
"""

import pytest
from urllib.parse import unquote_plus

from osint_tool.modules.dork_search import (
    build_dork_urls,
    run_dork_search,
    GENERAL_DORKS,
    GOV_DORKS,
    SOCIAL_DORKS,
    LEAK_DORKS,
    EMAIL_DORKS,
    USERNAME_DORKS,
    PHONE_DORKS,
    _render_dork,
    DorkSearchResult,
)


class TestRenderDork:
    def test_renders_name_placeholder(self):
        assert _render_dork('"{name}"', name="John Doe") == '"John Doe"'

    def test_renders_email_placeholder(self):
        assert _render_dork('"{email}"', email="a@b.com") == '"a@b.com"'

    def test_returns_none_when_placeholder_missing(self):
        assert _render_dork('"{name}"') is None

    def test_renders_multiple_placeholders(self):
        # If a template had two placeholders both supplied
        result = _render_dork('"{name}" "{email}"', name="Jane", email="jane@x.com")
        assert result == '"Jane" "jane@x.com"'


class TestBuildDorkUrls:
    def test_returns_list_of_urls(self):
        urls = build_dork_urls(name="John Doe")
        assert isinstance(urls, list)
        assert len(urls) > 0

    def test_urls_start_with_google(self):
        urls = build_dork_urls(name="John Doe")
        for u in urls:
            assert u.startswith("https://www.google.com/search?q=")

    def test_name_encoded_in_url(self):
        urls = build_dork_urls(name="John Doe")
        # At least one URL should contain the name
        combined = " ".join(unquote_plus(u) for u in urls)
        assert "John Doe" in combined

    def test_gov_only_flag(self):
        gov_urls = build_dork_urls(name="Jane Smith", gov_only=True)
        all_urls = build_dork_urls(name="Jane Smith", gov_only=False)
        # Gov-only should be a subset
        assert len(gov_urls) < len(all_urls)

    def test_email_dorks_included_when_email_given(self):
        urls_with_email = build_dork_urls(email="a@b.com")
        urls_without = build_dork_urls(name="John")
        # Email dorks produce distinct URLs
        assert len(urls_with_email) > 0

    def test_no_identifiers_returns_empty(self):
        urls = build_dork_urls()
        assert urls == []

    def test_username_dorks_included(self):
        urls = build_dork_urls(username="johndoe")
        combined = " ".join(unquote_plus(u) for u in urls)
        assert "johndoe" in combined

    def test_phone_dorks_included(self):
        urls = build_dork_urls(phone="+15551234567")
        combined = " ".join(unquote_plus(u) for u in urls)
        assert "+15551234567" in combined


class TestDorkTemplates:
    """Ensure gov dork templates cover expected platforms."""

    def test_gov_dorks_include_pacer(self):
        assert any("pacer.gov" in d for d in GOV_DORKS)

    def test_gov_dorks_include_sec(self):
        assert any("sec.gov" in d for d in GOV_DORKS)

    def test_gov_dorks_include_india(self):
        assert any("eci.gov.in" in d for d in GOV_DORKS)

    def test_gov_dorks_include_uk(self):
        assert any("companieshouse.gov.uk" in d for d in GOV_DORKS)

    def test_social_dorks_include_linkedin(self):
        assert any("linkedin.com" in d for d in SOCIAL_DORKS)

    def test_leak_dorks_include_pastebin(self):
        assert any("pastebin.com" in d for d in LEAK_DORKS)


class TestRunDorkSearchValidation:
    """Test the run_dork_search input validation (no network calls)."""

    def test_returns_result_object(self):
        # Providing no identifiers should return an error, not raise
        result = run_dork_search()
        assert isinstance(result, DorkSearchResult)
        assert len(result.errors) > 0

    def test_invalid_engine_returns_error(self):
        result = run_dork_search(name="Test", engine="invalid_engine")
        assert any("engine" in e.lower() or "Unknown" in e for e in result.errors)

    def test_result_stores_name(self):
        # Minimal call that would not make real HTTP requests (engine errors)
        result = run_dork_search(name="Alice", engine="invalid_engine")
        assert result.name == "Alice"
