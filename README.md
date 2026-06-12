# AI Threat Signal Intelligence Pipeline

> Adversarial AI content scraper, classifier, and threat intelligence dashboard — built for safety and security teams.

---

## Overview

The AI Threat Signal Intelligence Pipeline is an end-to-end data engineering system that monitors public sources — Reddit, HackerNews, arXiv, and CVE feeds — for emerging AI safety threats, jailbreak techniques, prompt injection patterns, and model vulnerability discussions.

Raw signals are scraped, deduplicated, classified by threat category, and surfaced as actionable intelligence via a REST API and Streamlit dashboard. The pipeline is architected to mirror production-grade GCP deployments (Pub/Sub → Cloud Run → CloudSQL → Cloud Composer) using local-equivalent tooling (Kafka → FastAPI workers → DuckDB → Airflow).

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    DATA SOURCES                     │
│   Reddit (PRAW)  │  HackerNews API  │  arXiv RSS   │
│                  CVE NVD Feed                       │
└──────────────┬──────────────────────────────────────┘
               │  Scrapy + BeautifulSoup crawlers
               ▼
┌─────────────────────────────────────────────────────┐
│              INGESTION LAYER                        │
│         Kafka Topic: raw_threat_signals             │
│     (GCP equivalent: Cloud Pub/Sub)                 │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│            PROCESSING WORKERS                       │
│   FastAPI + Python workers (Cloud Run equivalent)   │
│   - Deduplication (SHA-256 content hash)            │
│   - PII anonymization + masking                     │
│   - Threat category tagging                         │
│   - Severity scoring                                │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│              STORAGE LAYER                          │
│   Raw JSON → /data/raw/  (GCS equivalent)           │
│   Structured → DuckDB    (CloudSQL equivalent)      │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│           ORCHESTRATION (Airflow)                   │
│        Cloud Composer equivalent                    │
│   DAG: threat_ingestion_pipeline (daily)            │
│   DAG: dbt_transformation_pipeline (daily)          │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│         TRANSFORMATION LAYER (dbt)                  │
│   bronze → silver → gold medallion architecture     │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│              SERVING LAYER                          │
│   FastAPI REST endpoints  │  Streamlit Dashboard    │
└─────────────────────────────────────────────────────┘
```

---

## dbt Medallion Architecture

### Bronze — Raw Ingestion
| Model | Description |
|---|---|
| `bronze_reddit_posts` | Raw Reddit posts from r/MachineLearning, r/netsec, r/ArtificialIntelligence |
| `bronze_hn_stories` | HackerNews stories and comments matching threat keywords |
| `bronze_arxiv_papers` | arXiv abstracts tagged with adversarial ML / safety topics |
| `bronze_cve_records` | CVE NVD feed records for AI/ML-adjacent vulnerabilities |

### Silver — Cleaned & Classified
| Model | Description |
|---|---|
| `silver_threat_signals` | Deduplicated, anonymized signals with threat category tags |
| `silver_entity_mentions` | Model family and company mentions extracted per signal |
| `silver_source_velocity` | Daily post volume per source — spike detection |

### Gold — Intelligence Layer
| Model | Description |
|---|---|
| `gold_threat_signals` | Final enriched signals with severity index, served via API |
| `gold_emerging_threats` | Signals with >2x velocity spike in last 7 days |
| `gold_severity_index` | Composite score: engagement × novelty × recurrence |
| `gold_entity_risk_map` | Which model families appear most in adversarial discourse |

---

## Threat Taxonomy

Signals are classified into the following categories:

| Category | Examples |
|---|---|
| `jailbreak` | Prompt override techniques, role-play exploits |
| `prompt_injection` | Indirect injection via documents, tool outputs |
| `data_poisoning` | Training data manipulation, backdoor attacks |
| `model_extraction` | API-based model stealing, distillation attacks |
| `adversarial_inputs` | Adversarial examples, image perturbations |
| `supply_chain` | Malicious fine-tunes, compromised checkpoints |
| `infrastructure` | CVEs in ML serving stacks (TorchServe, Triton, etc.) |
| `policy_evasion` | Content filter bypasses, NSFW evasion techniques |

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/threats/latest` | Most recent 50 threat signals |
| `GET` | `/threats/{category}` | Signals filtered by threat category |
| `GET` | `/threats/emerging` | Signals with velocity spike in last 7 days |
| `GET` | `/threats/severity` | Signals sorted by severity index descending |
| `GET` | `/entities/{name}` | All signals mentioning a specific model or company |
| `GET` | `/health` | Pipeline health + last successful run timestamp |

---

## Tech Stack

| Layer | Tool | GCP Production Equivalent |
|---|---|---|
| Scraping | Scrapy, BeautifulSoup, PRAW | — |
| Ingestion | Apache Kafka (Docker) | Cloud Pub/Sub |
| Processing | Python workers, FastAPI | Cloud Run |
| Raw Storage | Local filesystem (`/data/raw/`) | Cloud Storage (GCS) |
| Database | DuckDB | CloudSQL / Cloud Spanner |
| Orchestration | Apache Airflow (Docker) | Cloud Composer |
| Transformation | dbt Core | — |
| Serving | FastAPI, Streamlit | Cloud Run |
| Testing | pytest | — |
| Containerization | Docker, Docker Compose | — |

> **GCP Note:** This pipeline is architected as a direct GCP-equivalent system. Kafka → Pub/Sub, DuckDB → CloudSQL, Airflow → Cloud Composer, local workers → Cloud Run. Migration path requires swapping connection strings and credentials — no architectural changes needed.

---

## Project Structure

```
ai-threat-signal-pipeline/
├── scrappers/
│   ├── reddit_scraper.py          # PRAW-based Reddit ingestion
│   ├── hn_scraper.py              # HackerNews API scraper
│   ├── arxiv_scraper.py           # arXiv RSS feed parser
│   └── cve_scraper.py             # NVD CVE feed scraper
├── ingestion/
│   ├── kafka_producer.py          # Publishes raw signals to Kafka
│   └── kafka_consumer.py          # Consumes and routes to DuckDB
├── processing/
│   ├── deduplicator.py            # SHA-256 content hash dedup
│   ├── anonymizer.py              # PII masking + anonymization
│   ├── classifier.py              # Threat category tagger
│   └── severity_scorer.py         # Composite severity index
├── dbt/
│   ├── models/
│   │   ├── bronze/
│   │   ├── silver/
│   │   └── gold/
│   ├── tests/
│   └── dbt_project.yml
├── airflow/
│   ├── dags/
│   │   ├── threat_ingestion_dag.py
│   │   └── dbt_transformation_dag.py
│   └── docker-compose.yml
├── api/
│   └── main.py                    # FastAPI REST endpoints
├── dashboard/
│   └── app.py                     # Streamlit threat dashboard
├── tests/
│   ├── test_scrapers.py
│   ├── test_processing.py
│   ├── test_dbt_models.py
│   └── test_api.py
├── data/
│   └── raw/                       # Raw JSON landing zone
├── docker-compose.yml             # Kafka + Airflow + app stack
├── requirements.txt
└── README.md
```

---

## Quickstart

### Prerequisites

- Python 3.11+
- Docker + Docker Compose
- Reddit API credentials (PRAW)

### Setup

```bash
git clone https://github.com/sajansshergill/ai-threat-signal-pipeline
cd ai-threat-signal-pipeline

# Start Kafka + Airflow
docker-compose up -d

# Install dependencies
pip install -r requirements.txt

# Configure credentials
cp .env.example .env
# Add REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USER_AGENT

# Classify and score raw ingested signals
python processing/classifier.py

# Run dbt transformations
cd dbt && dbt deps && dbt run && dbt test

# Start API server
uvicorn api.main:app --reload

# Launch dashboard
streamlit run dashboard/app.py
```

### Run scrapers manually

```bash
python scrappers/reddit_scraper.py
python scrappers/hn_scraper.py
python scrappers/arxiv_scraper.py
python scrappers/cve_scraper.py
```

---

## Testing

```bash
pytest tests/ -v
```

| Test Suite | Coverage |
|---|---|
| Scraper unit tests | Source connectivity, payload schema validation |
| Processing unit tests | Dedup logic, anonymization, category tagging |
| dbt schema tests | Not null, unique, accepted values across all models |
| API integration tests | Endpoint response codes, payload structure |

---

## Key Engineering Decisions

**Why Kafka over direct DB writes?**
Decouples scrapers from processing workers. Scrapers can burst without blocking downstream transformation — mirrors the Pub/Sub pattern used in production GCP pipelines.

**Why DuckDB?**
Zero-infrastructure columnar storage optimized for analytical workloads on text-heavy data. Swap for CloudSQL with a single connection string change for production deployment.

**Why SHA-256 deduplication before storage?**
The same jailbreak technique surfaces across Reddit, HN, and Twitter simultaneously. Content-hash dedup at ingestion prevents the same signal inflating severity scores downstream.

**Why a medallion architecture for threat data?**
Bronze preserves raw provenance for audit trails. Silver normalizes and anonymizes. Gold surfaces only actionable intelligence — consistent with how safety teams consume threat feeds.

---

## Author

**Sajan Singh Shergill**
M.S. Data Science, Pace University
[linkedin.com/in/sajanshergill](https://linkedin.com/in/sajanshergill) · [sajansshergill.github.io](https://sajansshergill.github.io) · sajansshergill@gmail.com
