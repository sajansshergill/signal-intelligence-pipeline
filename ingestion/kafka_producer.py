# ingestion/kafka_producer.py

import json
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient, NewTopic

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"

TOPICS = {
    "reddit":   "raw.reddit.signals",
    "hn":       "raw.hn.signals",
    "arxiv":    "raw.arxiv.signals",
    "cve":      "raw.cve.signals",
}

# single unified topic — consumer reads from here
UNIFIED_TOPIC = "raw.threat.signals"

TOPIC_CONFIG = {
    "num_partitions": 3,
    "replication_factor": 1,        # local single-broker setup
    "config": {
        "retention.ms": str(7 * 24 * 60 * 60 * 1000),   # 7 days
        "cleanup.policy": "delete",
    }
}


def build_producer() -> Producer:
    return Producer({
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "client.id": "threat-signal-producer",
        "acks": "all",                  # wait for all replicas
        "retries": 3,
        "retry.backoff.ms": 500,
        "compression.type": "gzip",     # compress text payloads
        "linger.ms": 10,                # small batching window
        "batch.size": 65536,            # 64KB batch
    })


def ensure_topics(topics: list[str]) -> None:
    """Create Kafka topics if they don't already exist."""
    admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS})
    existing = set(admin.list_topics(timeout=10).topics.keys())

    to_create = []
    for topic in topics:
        if topic not in existing:
            to_create.append(NewTopic(
                topic,
                num_partitions=TOPIC_CONFIG["num_partitions"],
                replication_factor=TOPIC_CONFIG["replication_factor"],
                config=TOPIC_CONFIG["config"],
            ))
            logger.info(f"Queuing topic creation: {topic}")
        else:
            logger.info(f"Topic already exists: {topic}")

    if to_create:
        fs = admin.create_topics(to_create)
        for topic, f in fs.items():
            try:
                f.result()
                logger.info(f"Topic created: {topic}")
            except Exception as e:
                logger.error(f"Failed to create topic {topic}: {e}")


def delivery_report(err, msg) -> None:
    """Callback fired once per message after broker ack."""
    if err:
        logger.error(f"Delivery failed | topic={msg.topic()} | {err}")
    else:
        logger.debug(
            f"Delivered | topic={msg.topic()} "
            f"partition={msg.partition()} "
            f"offset={msg.offset()}"
        )


def partition_key(record: dict) -> bytes:
    """
    Partition by source so all records from the same
    source land on the same partition — preserves ordering
    per source and simplifies consumer filtering.
    """
    source = record.get("source", "unknown")
    return source.encode("utf-8")


def enrich_record(record: dict, source_type: str) -> dict:
    """Add pipeline metadata before publishing."""
    return {
        **record,
        "pipeline_source": source_type,
        "published_at": datetime.now(tz=timezone.utc).isoformat(),
        "schema_version": "1.0",
    }


def publish_records(
    producer: Producer,
    records: list[dict],
    source_type: str,
    topic: str = UNIFIED_TOPIC,
) -> tuple[int, int]:
    """
    Publish a list of records to Kafka.
    Returns (success_count, failure_count).
    """
    success = 0
    failure = 0

    for record in records:
        try:
            enriched = enrich_record(record, source_type)
            payload = json.dumps(enriched, ensure_ascii=False).encode("utf-8")
            key = partition_key(enriched)

            producer.produce(
                topic=topic,
                key=key,
                value=payload,
                on_delivery=delivery_report,
            )
            success += 1

            # poll every 100 messages to drain delivery callbacks
            if success % 100 == 0:
                producer.poll(0)

        except BufferError:
            logger.warning("Producer buffer full — flushing...")
            producer.flush()
            # retry once after flush
            try:
                producer.produce(
                    topic=topic,
                    key=partition_key(record),
                    value=json.dumps(record).encode("utf-8"),
                    on_delivery=delivery_report,
                )
                success += 1
            except Exception as e:
                logger.error(f"Retry failed for record {record.get('content_hash', '')[:12]}: {e}")
                failure += 1

        except Exception as e:
            logger.error(f"Produce error: {e}")
            failure += 1

    # final flush — wait for all pending messages
    producer.flush(timeout=30)
    return success, failure


def publish_from_raw_files(source_type: str) -> tuple[int, int]:
    """
    Load the latest raw JSON file for a source and publish to Kafka.
    Used by Airflow DAG to trigger ingestion per source.
    """
    raw_dir = Path(f"data/raw/{source_type}")
    if not raw_dir.exists():
        logger.error(f"Raw directory not found: {raw_dir}")
        return 0, 0

    # pick the most recent file
    files = sorted(raw_dir.glob("*.json"), reverse=True)
    if not files:
        logger.warning(f"No raw files found in {raw_dir}")
        return 0, 0

    latest_file = files[0]
    logger.info(f"Publishing from: {latest_file}")

    with open(latest_file) as f:
        records = json.load(f)

    producer = build_producer()
    ensure_topics([UNIFIED_TOPIC])
    success, failure = publish_records(producer, records, source_type=source_type)

    logger.info(
        f"[{source_type.upper()}] Published {success} records | "
        f"Failed {failure} | Topic: {UNIFIED_TOPIC}"
    )
    return success, failure


def run_all() -> None:
    """Publish all sources in sequence — used for full pipeline runs."""
    producer = build_producer()
    ensure_topics([UNIFIED_TOPIC])

    source_types = ["reddit", "hn", "arxiv", "cve"]
    totals = {"success": 0, "failure": 0}

    for source_type in source_types:
        raw_dir = Path(f"data/raw/{source_type}")
        files = sorted(raw_dir.glob("*.json"), reverse=True) if raw_dir.exists() else []

        if not files:
            logger.warning(f"No files for source: {source_type} — skipping")
            continue

        with open(files[0]) as f:
            records = json.load(f)

        success, failure = publish_records(producer, records, source_type=source_type)
        totals["success"] += success
        totals["failure"] += failure

    logger.info(
        f"\nPipeline publish complete | "
        f"Total success: {totals['success']} | "
        f"Total failure: {totals['failure']}"
    )


if __name__ == "__main__":
    run_all()