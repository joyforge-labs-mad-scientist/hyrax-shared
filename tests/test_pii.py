"""Unit tests for hyrax_shared.pii.mask_email."""
import pytest

from hyrax_shared.pii import mask_email


@pytest.mark.parametrize("email,expected", [
    ("alice@example.com", "al***@example.com"),
    ("bob@corp.co.uk", "bo***@corp.co.uk"),
    ("a@x.com", "a***@x.com"),
    ("@example.com", "***@example.com"),
    ("verylongname@example.com", "ve***@example.com"),
    ("UPPER@EXAMPLE.COM", "UP***@EXAMPLE.COM"),
    ("user+tag@example.com", "us***@example.com"),
])
def test_mask_email_normal_cases(email, expected):
    assert mask_email(email) == expected


@pytest.mark.parametrize("invalid", ["", None, "no-at-sign", "   "])
def test_mask_email_invalid_returns_sentinel(invalid):
    assert mask_email(invalid) == "<invalid>"


def test_mask_email_is_deterministic():
    """Two calls with the same input return the same mask — required for log correlation."""
    assert mask_email("alice@example.com") == mask_email("alice@example.com")


def test_mask_email_distinguishes_different_users_same_domain():
    """Different local parts produce different masks — operators can still tell users apart."""
    assert mask_email("alice@example.com") != mask_email("bob@example.com")


def test_mask_email_preserves_full_domain():
    """The domain is retained in full — domains are not PII and are useful for debugging."""
    masked = mask_email("alice@subdomain.example.co.uk")
    assert masked.endswith("@subdomain.example.co.uk")
