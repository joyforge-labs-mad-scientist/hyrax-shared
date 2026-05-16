"""Unit tests for hyrax_shared.url_safety.validate_outbound_url."""
import socket
from unittest import mock

import pytest

from hyrax_shared.url_safety import validate_outbound_url


# ---------- Scheme + input shape ----------

def test_empty_url_rejected():
    is_valid, reason = validate_outbound_url("")
    assert is_valid is False
    assert reason


def test_none_url_rejected():
    is_valid, reason = validate_outbound_url(None)
    assert is_valid is False


@pytest.mark.parametrize("scheme", ["ftp", "file", "gopher", "ws", "wss"])
def test_non_http_schemes_rejected(scheme):
    is_valid, reason = validate_outbound_url(f"{scheme}://example.com")
    assert is_valid is False
    assert "scheme" in reason.lower()


# ---------- IPv4 literal hostnames ----------

@pytest.mark.parametrize("ip", ["127.0.0.1", "127.5.6.7"])
def test_ipv4_loopback_rejected(ip):
    is_valid, reason = validate_outbound_url(f"http://{ip}/")
    assert is_valid is False
    assert "loopback" in reason.lower()


def test_ipv4_azure_aws_metadata_rejected():
    """169.254.169.254 is the Azure IMDS / AWS metadata endpoint."""
    is_valid, reason = validate_outbound_url("http://169.254.169.254/metadata")
    assert is_valid is False
    assert "link-local" in reason.lower() or "metadata" in reason.lower()


@pytest.mark.parametrize("ip", [
    "10.0.0.1", "10.255.255.255",
    "172.16.0.1", "172.31.255.255",
    "192.168.1.1", "192.168.255.255",
])
def test_ipv4_rfc1918_rejected(ip):
    is_valid, reason = validate_outbound_url(f"http://{ip}/")
    assert is_valid is False
    assert "private" in reason.lower()


def test_ipv4_multicast_rejected():
    is_valid, reason = validate_outbound_url("http://224.0.0.1/")
    assert is_valid is False
    assert "multicast" in reason.lower()


# ---------- IPv6 literal hostnames ----------

def test_ipv6_loopback_rejected():
    is_valid, reason = validate_outbound_url("http://[::1]/")
    assert is_valid is False
    assert "loopback" in reason.lower()


def test_ipv6_link_local_fe80_rejected():
    is_valid, reason = validate_outbound_url("http://[fe80::1]/")
    assert is_valid is False
    assert "link-local" in reason.lower()


def test_ipv6_unique_local_fc00_rejected():
    """fc00::/7 is IPv6 ULA (treated as private by ipaddress.ip_address.is_private)."""
    is_valid, reason = validate_outbound_url("http://[fc00::1]/")
    assert is_valid is False
    assert "private" in reason.lower()


# ---------- DNS-based attacks ----------

def test_domain_resolving_to_private_ip_rejected():
    """Hostname that DNS-resolves to a private IP must be rejected post-resolution."""
    with mock.patch('hyrax_shared.url_safety.socket.getaddrinfo') as m:
        m.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('10.0.0.1', 0))]
        is_valid, reason = validate_outbound_url("http://attacker.example.com/")
    assert is_valid is False
    assert "private" in reason.lower()


def test_domain_resolving_to_metadata_ip_rejected():
    with mock.patch('hyrax_shared.url_safety.socket.getaddrinfo') as m:
        m.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('169.254.169.254', 0))]
        is_valid, reason = validate_outbound_url("http://attacker.example.com/")
    assert is_valid is False
    assert "link-local" in reason.lower() or "metadata" in reason.lower()


def test_domain_resolving_to_loopback_rejected():
    with mock.patch('hyrax_shared.url_safety.socket.getaddrinfo') as m:
        m.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0))]
        is_valid, reason = validate_outbound_url("http://attacker.example.com/")
    assert is_valid is False
    assert "loopback" in reason.lower()


# ---------- Metadata-endpoint pattern fallback ----------

def test_localhost_pattern_rejected_even_when_dns_fails():
    """If DNS doesn't resolve, the literal pattern check still catches 'localhost'."""
    with mock.patch('hyrax_shared.url_safety.socket.getaddrinfo') as m:
        m.side_effect = socket.gaierror("no resolution")
        is_valid, reason = validate_outbound_url("http://localhost/")
    assert is_valid is False
    assert "metadata" in reason.lower()


def test_metadata_google_internal_rejected():
    with mock.patch('hyrax_shared.url_safety.socket.getaddrinfo') as m:
        m.side_effect = socket.gaierror("no resolution")
        is_valid, reason = validate_outbound_url("http://metadata.google.internal/")
    assert is_valid is False
    assert "metadata" in reason.lower()


# ---------- DNS rebinding ----------

def test_dns_rebinding_caught_by_revalidation():
    """Simulate DNS rebinding: first resolution returns a public IP, second returns a private IP.
    Call sites must re-validate before each fetch - this test confirms each call re-resolves."""
    call_count = {'n': 0}

    def fake_getaddrinfo(host, port, *args, **kwargs):
        call_count['n'] += 1
        if call_count['n'] == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('8.8.8.8', 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('10.0.0.1', 0))]

    with mock.patch('hyrax_shared.url_safety.socket.getaddrinfo', side_effect=fake_getaddrinfo):
        first = validate_outbound_url("http://rebinding.example.com/")
        second = validate_outbound_url("http://rebinding.example.com/")

    assert first[0] is True, f"Expected first call valid, got: {first[1]}"
    assert second[0] is False, "Expected second call to catch the pivoted private IP"
    assert "private" in second[1].lower()


# ---------- Happy path ----------

def test_public_ip_literal_accepted():
    """Public IP literal (8.8.8.8) should be accepted - no private/loopback/metadata match."""
    is_valid, reason = validate_outbound_url("https://8.8.8.8/")
    assert is_valid is True, f"Expected valid, got: {reason}"


def test_public_domain_with_mocked_public_dns_accepted():
    """Domain resolving to a public IP should be accepted."""
    with mock.patch('hyrax_shared.url_safety.socket.getaddrinfo') as m:
        m.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
        is_valid, reason = validate_outbound_url("https://example.com/")
    assert is_valid is True, f"Expected valid, got: {reason}"
