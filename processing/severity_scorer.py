"""Deterministic severity scoring for classified threat signals."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

CATEGORY_WEIGHTS = {
    "jailbreak": 6.2,
    "prompt_injection": 7.0,
    "data_poisoning": 7.4,
    "model_extraction": 7.2,
    "adversarial_inputs": 6.6,
    "supply_chain": 8.0,
    "infrastructure": 7.8,
    "policy_evasion": 5.8,
    "privacy_attack": 7.1,
    "alignment_failure": 6.4,
    "unclassified": 2.0,
}

SEVERITY_BANDS = (
    (8.5, "CRITICAL"),
    (7.0, "HIGH"),
    (5.0, "MEDIUM"),
    (3.0, "LOW"),
    (0.0, "MINIMAL"),
)


def severity_band(score: float) -> str:
    for threshold, band in SEVERITY_BANDS:
        if score >= threshold:
            return band
    return "MINIMAL"


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _recency_boost(record: dict[str, Any]) -> float:
    signal_time = _parse_timestamp(
        record.get("created_utc")
        or record.get("published_utc")
        or record.get("modified_utc")
        or record.get("scraped_at")
    )
    if not signal_time:
        return 0.0

    age_days = max(
        0.0,
        (datetime.now(tz=timezone.utc) - signal_time.astimezone(timezone.utc)).days,
    )
    if age_days <= 7:
        return 0.8
    if age_days <= 30:
        return 0.4
    return 0.0


def _engagement_boost(record: dict[str, Any]) -> float:
    score = float(record.get("score") or 0)
    comments = float(record.get("num_comments") or 0)
    authors = float(record.get("author_count") or 0)
    engagement = max(score, 0) + comments * 1.5 + authors
    if engagement <= 0:
        return 0.0
    return min(1.2, math.log10(engagement + 1) * 0.45)


def score_signal(
    record: dict[str, Any],
    primary_category: str,
    categories: list[str],
) -> tuple[float, str, dict[str, float]]:
    """Return severity score, band, and component details."""
    cvss_score = record.get("cvss_score")
    base = float(cvss_score) if cvss_score is not None else CATEGORY_WEIGHTS[primary_category]

    breadth_boost = min(0.8, max(0, len(categories) - 1) * 0.25)
    recency_boost = _recency_boost(record)
    engagement_boost = _engagement_boost(record)
    exploit_boost = 0.5 if record.get("references") else 0.0

    score = min(10.0, round(base + breadth_boost + recency_boost + engagement_boost + exploit_boost, 2))
    components = {
        "base": round(base, 2),
        "breadth_boost": round(breadth_boost, 2),
        "recency_boost": round(recency_boost, 2),
        "engagement_boost": round(engagement_boost, 2),
        "exploit_reference_boost": round(exploit_boost, 2),
    }
    return score, severity_band(score), components
