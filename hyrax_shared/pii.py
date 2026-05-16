"""PII masking helpers for log output.

The mask must be deterministic so operators can correlate multiple log lines
for the same customer without seeing the raw value (P1-9, May 2026 security
review). Use these helpers in any log statement that would otherwise emit
customer email addresses.
"""


def mask_email(email: str) -> str:
    """Return a masked form of an email address suitable for log output.

    Format: `<first 2 chars of local>***@<domain>`. Deterministic for a
    given input — two log lines about the same customer mask identically.

    Returns `<invalid>` for empty input or anything lacking a `@`.
    """
    if not email or "@" not in email:
        return "<invalid>"
    local, _, domain = email.partition("@")
    return f"{local[:2]}***@{domain}"
