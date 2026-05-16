"""
SSRF guard for outbound HTTP fetches.

When any service in the Hyrax pipeline fetches HTTP(S) on behalf of a
user-controlled value (e.g. an email domain, a webhook URL), an attacker
can submit a value whose hostname (or DNS resolution) points to:
- The cloud metadata endpoint (169.254.169.254 on Azure / AWS) -> identity tokens leak
- A private IP inside the VPC -> internal-service attacks
- Loopback -> local-service attacks
- A name that resolves to any of the above (post-resolution)

This validator MUST be called before any outbound fetch where the URL is
even partly user-controlled.

Originally lived in two duplicates (Hyrax-QA-Webhook/validation.py and
Hyrax-QA-Main/utils/url_safety.py) before consolidation into this package.
"""

import ipaddress
import re
import socket
from typing import Tuple
from urllib.parse import urlparse


_METADATA_PATTERNS = [
    r'169\.254\.169\.254',          # AWS / Azure IMDS
    r'metadata\.google\.internal',   # GCP metadata
    r'localhost',
    r'127\.\d+\.\d+\.\d+',
]


def validate_outbound_url(url: str) -> Tuple[bool, str]:
    """
    Validate that `url` is safe to fetch.

    Security checks:
    - Must be a non-empty string
    - Must be an http or https URL
    - Must have a hostname
    - If hostname is an IP literal: reject loopback, link-local, private (RFC 1918),
      multicast (covers both IPv4 and IPv6 via the ipaddress module)
    - If hostname is a name: resolve to IP(s) and reject any that fall in the same blocked ranges
      (closes the SSRF-via-DNS hole; on each call, the resolution is fresh - call sites should
      re-validate before each fetch to also close the DNS-rebinding window)
    - Reject common cloud metadata endpoints by pattern (covers proxy variants and DNS aliases)

    Returns (is_valid, reason). reason is empty when is_valid is True.
    """
    if not url or not isinstance(url, str):
        return False, "URL is required and must be a string"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL format: {e}"

    if parsed.scheme not in ('http', 'https'):
        return False, f"Invalid URL scheme: {parsed.scheme}. Only http and https are allowed"

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname"

    # IP-literal hostname
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback:
            return False, f"Loopback addresses are not allowed: {hostname}"
        if ip.is_link_local:
            return False, f"Link-local addresses are not allowed: {hostname}"
        if ip.is_private:
            return False, f"Private IP addresses are not allowed: {hostname}"
        if ip.is_multicast:
            return False, f"Multicast addresses are not allowed: {hostname}"
    except ValueError:
        # Hostname is a name - resolve and check each IP
        try:
            resolved = socket.getaddrinfo(hostname, None)
            for family, type_, proto, canonname, sockaddr in resolved:
                try:
                    resolved_ip = ipaddress.ip_address(sockaddr[0])
                    if resolved_ip.is_loopback:
                        return False, f"Domain resolves to loopback: {hostname} -> {sockaddr[0]}"
                    if resolved_ip.is_link_local:
                        return False, f"Domain resolves to link-local: {hostname} -> {sockaddr[0]}"
                    if resolved_ip.is_private:
                        return False, f"Domain resolves to private address: {hostname} -> {sockaddr[0]}"
                    if resolved_ip.is_multicast:
                        return False, f"Domain resolves to multicast: {hostname} -> {sockaddr[0]}"
                except ValueError:
                    continue
        except socket.gaierror:
            # Unresolvable - let the fetch fail naturally rather than blocking pre-emptively
            pass

    for pattern in _METADATA_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE):
            return False, f"Metadata endpoints are not allowed: {hostname}"

    return True, ""
