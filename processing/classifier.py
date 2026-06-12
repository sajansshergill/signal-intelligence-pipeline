# processing/classifier.py

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

try:
    from processing.anonymizer import mask_pii
    from processing.deduplicator import content_hash
    from processing.severity_scorer import score_signal
except ModuleNotFoundError:  # Allows `python processing/classifier.py` from repo root.
    from anonymizer import mask_pii
    from deduplicator import content_hash
    from severity_scorer import score_signal

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DUCKDB_PATH = "data/threat_signals.duckdb"

THREAT_TAXONOMY: dict[str, tuple[str, ...]] = {
    "jailbreak": (
        "jailbreak", "jail break", "dan", "do anything now", "roleplay exploit",
        "system prompt bypass", "developer mode", "grandma exploit",
    ),
    "prompt_injection": (
        "prompt injection", "indirect injection", "ignore previous instructions",
        "system prompt leak", "tool injection", "rag injection", "instruction override",
    ),
    "data_poisoning": (
        "data poisoning", "poisoned dataset", "backdoor", "training data attack",
        "corpus poisoning", "label flipping", "trojaned data",
    ),
    "model_extraction": (
        "model extraction", "model stealing", "distillation attack", "api stealing",
        "membership inference", "model inversion", "shadow model",
    ),
    "adversarial_inputs": (
        "adversarial example", "adversarial input", "evasion attack",
        "perturbation", "adversarial patch", "gradient attack",
    ),
    "supply_chain": (
        "supply chain", "malicious model", "malicious fine-tune", "compromised checkpoint",
        "pickle exploit", "dependency confusion", "model hub", "hugging face",
    ),
    "infrastructure": (
        "cve-", "remote code execution", "rce", "privilege escalation", "torchserve",
        "triton", "mlflow", "kubeflow", "ray", "fastapi", "gradio", "streamlit",
        "vulnerability", "exploit", "deserialization",
    ),
    "policy_evasion": (
        "policy evasion", "content filter bypass", "safety filter", "guardrail bypass",
        "nsfw bypass", "unsafe output", "moderation bypass",
    ),
    "privacy_attack": (
        "privacy attack", "pii leak", "data leak", "prompt leak", "credential leak",
        "secret extraction", "exfiltration", "training data extraction",
    ),
    "alignment_failure": (
        "alignment failure", "reward hacking", "specification gaming", "deceptive",
        "misalignment", "power seeking", "red team",
    ),
}

CATEGORY_PRIORITY = {
    "infrastructure": 95,
    "supply_chain": 90,
    "data_poisoning": 85,
    "prompt_injection": 80,
    "model_extraction": 75,
    "privacy_attack": 72,
    "adversarial_inputs": 70,
    "jailbreak": 65,
    "alignment_failure": 60,
    "policy_evasion": 55,
    "unclassified": 0,
}


def build_signal_text(record: dict[str, Any]) -> str:
    return " ".join(
        str(record.get(field) or "")
        for field in ("title", "body", "abstract", "description", "cve_id", "severity")
    )


def classify_text(text: str, source: str | None = None) -> tuple[str, list[str], dict[str, int]]:
    """Classify a signal into the project taxonomy using transparent keyword rules."""
    text_lower = text.lower()
    scores: dict[str, int] = {}

    for category, keywords in THREAT_TAXONOMY.items():
        count = 0
        for keyword in keywords:
            count += len(re.findall(re.escape(keyword), text_lower))
        if count:
            scores[category] = count

    if source == "nvd_cve" and "infrastructure" not in scores:
        scores["infrastructure"] = 1

    if not scores:
        return "unclassified", ["unclassified"], {"unclassified": 1}

    categories = sorted(
        scores,
        key=lambda category: (scores[category], CATEGORY_PRIORITY[category]),
        reverse=True,
    )
    return categories[0], categories, scores


def processed_row(record: dict[str, Any]) -> dict[str, Any]:
    """Build one processed_signals row from one raw_signals row."""
    anonymized_title = mask_pii(record.get("title"))
    anonymized_body = mask_pii(record.get("body"))
    anonymized_abstract = mask_pii(record.get("abstract"))
    anonymized_description = mask_pii(record.get("description"))

    enriched_record = {
        **record,
        "title": anonymized_title,
        "body": anonymized_body,
        "abstract": anonymized_abstract,
        "description": anonymized_description,
    }

    digest = record.get("content_hash") or content_hash(build_signal_text(enriched_record))
    text = build_signal_text(enriched_record)
    primary_category, categories, category_scores = classify_text(
        text,
        source=record.get("source"),
    )
    severity_score, severity_band, severity_components = score_signal(
        enriched_record,
        primary_category,
        categories,
    )

    return {
        "content_hash": digest,
        "source": record.get("source"),
        "primary_category": primary_category,
        "threat_categories": json.dumps(categories),
        "category_scores": json.dumps(category_scores, sort_keys=True),
        "severity_score": severity_score,
        "severity_band": severity_band,
        "severity_components": json.dumps(severity_components, sort_keys=True),
        "processed_at": datetime.now(tz=timezone.utc).isoformat(),
    }


def init_processed_table(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS processed_signals (
            content_hash        VARCHAR PRIMARY KEY,
            source              VARCHAR NOT NULL,
            primary_category    VARCHAR NOT NULL,
            threat_categories   VARCHAR NOT NULL,
            category_scores     VARCHAR NOT NULL,
            severity_score      DOUBLE NOT NULL,
            severity_band       VARCHAR NOT NULL,
            severity_components VARCHAR NOT NULL,
            processed_at        TIMESTAMPTZ NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_processed_category
        ON processed_signals (primary_category)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_processed_severity
        ON processed_signals (severity_score)
    """)


def fetch_unprocessed(
    conn: duckdb.DuckDBPyConnection,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    limit_clause = f"LIMIT {int(limit)}" if limit else ""
    return conn.execute(f"""
        SELECT
            r.content_hash,
            r.source,
            r.title,
            r.body,
            r.abstract,
            r.description,
            r.cve_id,
            r.score,
            r.num_comments,
            r.author_count,
            r.cvss_score,
            r.severity,
            r.references,
            r.created_utc,
            r.published_utc,
            r.modified_utc,
            r.scraped_at
        FROM raw_signals r
        LEFT JOIN processed_signals p
            ON r.content_hash = p.content_hash
        WHERE p.content_hash IS NULL
          AND r.content_hash IS NOT NULL
        ORDER BY COALESCE(r.created_utc, r.published_utc, r.modified_utc, r.scraped_at) DESC
        {limit_clause}
    """).fetchdf().to_dict(orient="records")


def upsert_processed_rows(
    conn: duckdb.DuckDBPyConnection,
    rows: list[dict[str, Any]],
) -> int:
    if not rows:
        return 0

    columns = list(rows[0].keys())
    placeholders = ", ".join(["?" for _ in columns])
    column_names = ", ".join(columns)
    insert_sql = f"INSERT INTO processed_signals ({column_names}) VALUES ({placeholders})"

    conn.begin()
    try:
        for row in rows:
            conn.execute(
                "DELETE FROM processed_signals WHERE content_hash = ?",
                [row["content_hash"]],
            )
            conn.execute(insert_sql, [row[column] for column in columns])
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return len(rows)


def process_raw_signals(db_path: str = DUCKDB_PATH, limit: int | None = None) -> int:
    """Classify raw_signals rows and persist processed_signals for dbt."""
    if not Path(db_path).exists():
        raise FileNotFoundError(f"DuckDB database not found: {db_path}")

    conn = duckdb.connect(db_path)
    try:
        init_processed_table(conn)
        raw_rows = fetch_unprocessed(conn, limit=limit)
        processed = [processed_row(row) for row in raw_rows]
        written = upsert_processed_rows(conn, processed)
        logger.info("Processed %s raw signals", written)
        return written
    finally:
        conn.close()


if __name__ == "__main__":
    process_raw_signals()
