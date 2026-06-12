"""PII masking helpers for raw public threat signals."""

from __future__ import annotations

import re

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HANDLE_RE = re.compile(r"(?<!\w)@[A-Za-z0-9_]{3,30}\b")


def mask_pii(text: str | None) -> str | None:
    """Mask common direct identifiers while preserving useful technical context."""
    if text is None:
        return None

    masked = EMAIL_RE.sub("[email]", text)
    masked = PHONE_RE.sub("[phone]", masked)
    masked = IPV4_RE.sub("[ip]", masked)
    masked = HANDLE_RE.sub("[handle]", masked)
    return masked


def anonymize_record(record: dict) -> dict:
    """Return a copy of a record with text fields anonymized."""
    cleaned = dict(record)
    for field in ("title", "body", "abstract", "description"):
        cleaned[field] = mask_pii(cleaned.get(field))
    cleaned["author"] = "[anonymized]" if cleaned.get("author") else cleaned.get("author")
    return cleaned
