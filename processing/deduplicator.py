# processing/deduplicator.py

from __future__ import annotations

import hashlib
import html
import re
from collections.abc import Iterable
from typing import Any

WHITESPACE_RE = re.compile(r"\s+")
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)


def normalize_text(value: str | None) -> str:
    """Normalize text before hashing so superficial formatting changes dedupe."""
    if not value:
        return ""

    text = html.unescape(value)
    text = URL_RE.sub("", text)
    text = WHITESPACE_RE.sub(" ", text)
    return text.strip().lower()


def content_hash(*parts: str | None) -> str:
    """Build the canonical SHA-256 hash used across the pipeline."""
    normalized = " ".join(
        part for part in (normalize_text(value) for value in parts) if part
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def record_text(record: dict[str, Any]) -> str:
    """Return the best available text body for a heterogeneous signal record."""
    return " ".join(
        str(record.get(field) or "")
        for field in ("title", "body", "abstract", "description")
    ).strip()


def is_duplicate(record: dict[str, Any], seen_hashes: set[str]) -> bool:
    """Check and update a seen-hash set for one record."""
    digest = record.get("content_hash") or content_hash(record_text(record))
    if digest in seen_hashes:
        return True

    seen_hashes.add(digest)
    record["content_hash"] = digest
    return False


def dedupe_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate records while preserving first-seen order."""
    seen_hashes: set[str] = set()
    unique: list[dict[str, Any]] = []

    for record in records:
        candidate = dict(record)
        if is_duplicate(candidate, seen_hashes):
            continue
        unique.append(candidate)

    return unique
