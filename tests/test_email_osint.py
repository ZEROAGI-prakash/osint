"""
Tests for the email_osint module.

Network-dependent calls (HIBP, Gravatar, GitHub) are mocked.
"""

import pytest
from unittest.mock import patch, MagicMock

from osint_tool.modules.email_osint import (
    run_email_osint,
    _validate_format,
    _gravatar_url,
    EmailOsintResult,
    DISPOSABLE_DOMAINS,
)


class TestValidateFormat:
    def test_valid_email(self):
        assert _validate_format("user@example.com") is True

    def test_valid_email_with_plus(self):
        assert _validate_format("user+tag@example.co.uk") is True

    def test_invalid_no_at(self):
        assert _validate_format("userexample.com") is False

    def test_invalid_no_domain(self):
        assert _validate_format("user@") is False

    def test_invalid_empty(self):
        assert _validate_format("") is False

    def test_invalid_spaces(self):
        assert _validate_format("user @example.com") is False


class TestGravatarUrl:
    def test_returns_url(self):
        url = _gravatar_url("test@example.com")
        assert url.startswith("https://www.gravatar.com/avatar/")
        assert url.endswith("?d=404")

    def test_consistent_hash(self):
        url1 = _gravatar_url("Test@Example.COM")
        url2 = _gravatar_url("test@example.com")
        # Should be identical (lowercased + stripped)
        assert url1 == url2


class TestDisposableDomains:
    def test_known_disposable_is_in_set(self):
        assert "mailinator.com" in DISPOSABLE_DOMAINS

    def test_gmail_not_disposable(self):
        assert "gmail.com" not in DISPOSABLE_DOMAINS


class TestRunEmailOsint:
    def test_invalid_format_returns_early(self):
        result = run_email_osint("not-an-email")
        assert result.is_valid_format is False
        assert len(result.errors) > 0

    @patch("osint_tool.modules.email_osint.requests.Session")
    @patch("osint_tool.modules.email_osint._get_mx")
    def test_valid_email_sets_domain(self, mock_mx, mock_session_cls):
        mock_mx.return_value = (["mail.example.com"], None)
        session = MagicMock()
        session.head.return_value.status_code = 404
        session.get.return_value.status_code = 404
        mock_session_cls.return_value = session

        result = run_email_osint("alice@example.com")
        assert result.domain == "example.com"
        assert result.is_valid_format is True

    @patch("osint_tool.modules.email_osint.requests.Session")
    @patch("osint_tool.modules.email_osint._get_mx")
    def test_disposable_email_flagged(self, mock_mx, mock_session_cls):
        mock_mx.return_value = ([], None)
        session = MagicMock()
        session.head.return_value.status_code = 404
        session.get.return_value.status_code = 404
        mock_session_cls.return_value = session

        result = run_email_osint("test@mailinator.com")
        assert result.is_disposable is True

    @patch("osint_tool.modules.email_osint.requests.Session")
    @patch("osint_tool.modules.email_osint._get_mx")
    def test_no_breaches_on_404(self, mock_mx, mock_session_cls):
        mock_mx.return_value = ([], None)
        resp = MagicMock()
        resp.status_code = 404
        session = MagicMock()
        session.head.return_value = resp
        session.get.return_value = resp
        mock_session_cls.return_value = session

        result = run_email_osint("nobody@example.com")
        assert result.breaches == []
