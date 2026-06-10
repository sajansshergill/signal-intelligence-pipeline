# ingestion/kafka_consumer.py

import json
import logging
import duckdb
from datetime import datetime, timezone
from pathlib import Path
from confluent_kafka import Consumer, KafkaError, KafkaException

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
UNIFIED_TOPIC = "raw.threat.signals"
DUCKDB_PATH = "data/threat_signals.duckdb"
CONSUMER_GROUP = "threat-signal-consumer-group"

# flush to DuckDB every N messages or N seconds
BATCH_SIZE = 50
POLL_TIMEOUT_SECONDS = 1.0


def build_consumer() -> Consumer:
    return Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "group.id": CONSUMER_GROUP,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,        # manual commit after DuckDB write
        "max.poll.interval.ms": 300000,
        "session.timeout.ms": 30000,
        "fetch.min.bytes": 1,
        "fetch.wait.max.ms": 500,
    })


def init_duckdb(db_path: str) -> duckdb.DuckDBPyConnection:
    """Initialize DuckDB and create raw signals table if not exists."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(db_path)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_signals (
            -- identity
            content_hash        VARCHAR PRIMARY KEY,
            source              VARCHAR NOT NULL,
            pipeline_source     VARCHAR,
            schema_version      VARCHAR,

            -- content
            title               VARCHAR,
            body                VARCHAR,
            abstract            VARCHAR,
            description         VARCHAR,
            url                 VARCHAR,
            pdf_url             VARCHAR,

            -- source-specific fields
            post_id             VARCHAR,
            comment_id          VARCHAR,
            item_id             VARCHAR,
            arxiv_id            VARCHAR,
            cve_id              VARCHAR,
            subreddit           VARCHAR,

            -- engagement signals
            score               INTEGER,
            num_comments        INTEGER,
            author_count        INTEGER,
            cvss_score          DOUBLE,
            severity            VARCHAR,
            severity_rank       INTEGER,

            -- structured fields stored as JSON strings
            categories          VARCHAR,    -- JSON array
            cwe_ids             VARCHAR,    -- JSON array
            references          VARCHAR,    -- JSON array

            -- timestamps
            created_utc         TIMESTAMPTZ,
            published_utc       TIMESTAMPTZ,
            modified_utc        TIMESTAMPTZ,
            updated_utc         TIMESTAMPTZ,
            scraped_at          TIMESTAMPTZ,
            published_at        TIMESTAMPTZ,
            ingested_at         TIMESTAMPTZ DEFAULT NOW(),
        )
    """)

    # indexes for common query patterns
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_source
        ON raw_signals (source)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_ingested_at
        ON raw_signals (ingested_at)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_severity_rank
        ON raw_signals (severity_rank)
    """)

    logger.info(f"DuckDB initialized: {db_path}")
    return conn


def safe_ts(value: str | None) -> str | None:
    """Safely parse ISO timestamp strings — returns None on failure."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).isoformat()
    except Exception:
        return None


def flatten_record(record: dict) -> dict:
    """
    Normalize a raw Kafka message payload into a flat
    dict matching the DuckDB raw_signals schema.
    JSON arrays are serialized to strings for storage.
    """
    return {
        "content_hash":     record.get("content_hash"),
        "source":           record.get("source"),
        "pipeline_source":  record.get("pipeline_source"),
        "schema_version":   record.get("schema_version"),
        "title":            record.get("title"),
        "body":             record.get("body"),
        "abstract":         record.get("abstract"),
        "description":      record.get("description"),
        "url":              record.get("url"),
        "pdf_url":          record.get("pdf_url"),
        "post_id":          record.get("post_id"),
        "comment_id":       record.get("comment_id"),
        "item_id":          str(record["item_id"]) if record.get("item_id") else None,
        "arxiv_id":         record.get("arxiv_id"),
        "cve_id":           record.get("cve_id"),
        "subreddit":        record.get("subreddit"),
        "score":            record.get("score"),
        "num_comments":     record.get("num_comments"),
        "author_count":     record.get("author_count"),
        "cvss_score":       record.get("cvss_score"),
        "severity":         record.get("severity"),
        "severity_rank":    record.get("severity_rank"),
        "categories":       json.dumps(record["categories"]) if record.get("categories") else None,
        "cwe_ids":          json.dumps(record["cwe_ids"]) if record.get("cwe_ids") else None,
        "references":       json.dumps(record["references"]) if record.get("references") else None,
        "created_utc":      safe_ts(record.get("created_utc")),
        "published_utc":    safe_ts(record.get("published_utc")),
        "modified_utc":     safe_ts(record.get("modified_utc")),
        "updated_utc":      safe_ts(record.get("updated_utc")),
        "scraped_at":       safe_ts(record.get("scraped_at")),
        "published_at":     safe_ts(record.get("published_at")),
        "ingested_at":      datetime.now(tz=timezone.utc).isoformat(),
    }


def write_batch(conn: duckdb.DuckDBPyConnection, batch: list[dict]) -> int:
    """
    Write a batch of records to DuckDB.
    Uses INSERT OR IGNORE on content_hash to handle duplicates.
    Returns number of records written.
    """
    if not batch:
        return 0

    flattened = [flatten_record(r) for r in batch]

    # filter out records missing content_hash
    valid = [r for r in flattened if r.get("content_hash")]
    if not valid:
        return 0

    columns = list(valid[0].keys())
    placeholders = ", ".join(["?" for _ in columns])
    col_names = ", ".join(columns)

    insert_sql = f"""
        INSERT OR IGNORE INTO raw_signals ({col_names})
        VALUES ({placeholders})
    """

    rows = [tuple(r[col] for col in columns) for r in valid]

    try:
        conn.executemany(insert_sql, rows)
        logger.info(f"Wrote {len(valid)} records to DuckDB")
        return len(valid)
    except Exception as e:
        logger.error(f"DuckDB write error: {e}")
        return 0


def run(max_messages: int | None = None) -> None:
    """
    Main consumer loop.
    Polls Kafka, batches records, writes to DuckDB, commits offsets.
    Runs indefinitely unless max_messages is set (useful for testing).
    """
    consumer = build_consumer()
    conn = init_duckdb(DUCKDB_PATH)
    consumer.subscribe([UNIFIED_TOPIC])

    batch: list[dict] = []
    total_written = 0
    total_consumed = 0

    logger.info(f"Consumer started | topic={UNIFIED_TOPIC} | group={CONSUMER_GROUP}")

    try:
        while True:
            msg = consumer.poll(timeout=POLL_TIMEOUT_SECONDS)

            if msg is None:
                # no message — flush partial batch if sitting idle
                if batch:
                    written = write_batch(conn, batch)
                    total_written += written
                    consumer.commit(asynchronous=False)
                    batch.clear()
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    logger.debug(
                        f"Reached end of partition: "
                        f"{msg.topic()} [{msg.partition()}] "
                        f"@ offset {msg.offset()}"
                    )
                    continue
                raise KafkaException(msg.error())

            # decode and parse message
            try:
                record = json.loads(msg.value().decode("utf-8"))
                batch.append(record)
                total_consumed += 1
            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode message: {e}")
                continue

            # flush batch when size threshold hit
            if len(batch) >= BATCH_SIZE:
                written = write_batch(conn, batch)
                total_written += written
                consumer.commit(asynchronous=False)     # commit after successful write
                batch.clear()
                logger.info(
                    f"Batch flushed | consumed={total_consumed} | "
                    f"written={total_written}"
                )

            if max_messages and total_consumed >= max_messages:
                logger.info(f"Reached max_messages={max_messages} — stopping")
                break

    except KeyboardInterrupt:
        logger.info("Consumer interrupted by user")

    finally:
        # flush remaining batch on shutdown
        if batch:
            write_batch(conn, batch)
            consumer.commit(asynchronous=False)

        consumer.close()
        conn.close()
        logger.info(
            f"Consumer shut down | "
            f"total consumed={total_consumed} | "
            f"total written={total_written}"
        )


if __name__ == "__main__":
    run()