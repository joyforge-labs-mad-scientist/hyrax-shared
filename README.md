# hyrax-shared

Shared Python utilities for the Hyrax pre-KYB pipeline. Consumed by `Hyrax-QA-API`, `Hyrax-QA-Main`, and `Hyrax-QA-Webhook` to avoid drift between identical helpers (most importantly: the outbound URL SSRF guard).

## Install

Pin by tag (preferred — reproducible builds):

```bash
pip install "hyrax-shared @ git+https://github.com/joyforge-labs-mad-scientist/hyrax-shared.git@v0.1.0"
```

Or via `requirements.txt`:

```
hyrax-shared @ git+https://github.com/joyforge-labs-mad-scientist/hyrax-shared.git@v0.1.0
```

## What's in it

### `hyrax_shared.url_safety.validate_outbound_url(url) -> (bool, str)`

SSRF guard for outbound HTTP fetches. Call before every outbound `aiohttp` / `httpx` / `requests` call that uses a user-controlled URL.

Checks:
- Scheme must be `http` or `https`
- Hostname must exist
- IP-literal hostnames: reject loopback, link-local, RFC 1918 private, multicast (IPv4 + IPv6 via `ipaddress` module)
- Name hostnames: resolve via `socket.getaddrinfo` and re-check resolved IPs (closes the SSRF-via-DNS hole)
- Pattern fallback: block known cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `localhost`, `127.x.y.z`) even when DNS doesn't resolve

Returns `(True, "")` if the URL is safe, `(False, "<reason>")` otherwise.

Call it fresh before each fetch — that closes the DNS-rebinding window (where DNS returns a public IP at validate time and a private IP at fetch time).

```python
from hyrax_shared.url_safety import validate_outbound_url

is_safe, reason = validate_outbound_url(url)
if not is_safe:
    logger.warning(f"[SSRF] Blocked: {reason}")
    return None
# proceed with outbound fetch
```

## Tests

```bash
pip install -e ".[test]"
pytest -v
```

28 unit tests cover IPv4 + IPv6 IP-literal rejection, DNS-resolution-to-private-IP, metadata-endpoint patterns, and DNS rebinding (mocked).

## Versioning

Semantic versioning. The validate_outbound_url contract is `(url: str) -> (bool, str)` — additive changes to the rule set (new metadata endpoints, etc.) are minor bumps; signature changes are major bumps.

## License

MIT — see [LICENSE](LICENSE).
