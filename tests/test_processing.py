from datetime import datetime, timezone

import duckdb

from processing.anonymizer import mask_pii
from processing.classifier import init_processed_table, processed_row, upsert_processed_rows
from processing.deduplicator import dedupe_records


def test_mask_pii_redacts_common_identifiers():
    text = "Email admin@example.com from @securityteam or 192.168.1.10."

    masked = mask_pii(text)

    assert "admin@example.com" not in masked
    assert "@securityteam" not in masked
    assert "192.168.1.10" not in masked
    assert "[email]" in masked
    assert "[handle]" in masked
    assert "[ip]" in masked


def test_dedupe_records_preserves_first_seen_order():
    records = [
        {"title": "Prompt injection in RAG", "body": "Ignore previous instructions"},
        {"title": "Prompt injection in RAG", "body": "Ignore previous instructions"},
        {"title": "TorchServe CVE", "description": "Remote code execution"},
    ]

    unique = dedupe_records(records)

    assert len(unique) == 2
    assert unique[0]["title"] == "Prompt injection in RAG"
    assert unique[1]["title"] == "TorchServe CVE"


def test_processed_row_classifies_and_scores_signal():
    row = processed_row({
        "content_hash": "abc123",
        "source": "hackernews",
        "title": "Prompt injection attack against RAG tools",
        "body": "Ignore previous instructions and exfiltration of secrets",
        "score": 120,
        "num_comments": 18,
        "created_utc": datetime.now(tz=timezone.utc).isoformat(),
    })

    assert row["content_hash"] == "abc123"
    assert row["primary_category"] == "prompt_injection"
    assert row["severity_score"] >= 7.0
    assert row["severity_band"] in {"HIGH", "CRITICAL"}


def test_upsert_processed_rows_writes_duckdb_contract():
    conn = duckdb.connect(":memory:")
    init_processed_table(conn)
    row = processed_row({
        "content_hash": "cve123",
        "source": "nvd_cve",
        "title": "CVE-2026-0001",
        "description": "TorchServe remote code execution vulnerability",
        "cvss_score": 9.8,
        "published_utc": datetime.now(tz=timezone.utc).isoformat(),
    })

    written = upsert_processed_rows(conn, [row])

    stored = conn.execute("""
        SELECT primary_category, severity_band
        FROM processed_signals
        WHERE content_hash = 'cve123'
    """).fetchone()
    assert written == 1
    assert stored == ("infrastructure", "CRITICAL")
