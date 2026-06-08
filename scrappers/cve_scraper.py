# scrapers/cve_scraper.py

import requests
import json
import hashlib
import logging
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# NVD API v2 — no API key required, higher rate limits with key
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RAW_OUTPUT_DIR = Path("data/raw/cve")
RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "ai-threat-pipeline/1.0"})

# keyword filter — CVEs relevant to AI/ML infrastructure
AI_ML_KEYWORDS = [
    # frameworks
    "tensorflow", "pytorch", "keras", "hugging face", "transformers",
    "scikit-learn", "xgboost", "lightgbm", "onnx", "triton",
    # serving infrastructure
    "torchserve", "mlflow", "kubeflow", "ray", "bentoml", "seldon",
    "nvidia triton", "tensorflow serving", "fastapi", "gradio", "streamlit",
    # vector DBs and RAG infrastructure
    "chroma", "pinecone", "weaviate", "qdrant", "faiss", "milvus",
    # LLM platforms
    "langchain", "llamaindex", "openai", "anthropic", "ollama",
    # orchestration
    "airflow", "prefect", "dagster", "metaflow",
    # general AI/ML
    "machine learning", "deep learning", "neural network", "llm",
    "large language model", "generative ai", "diffusion model",
]

SEVERITY_MAP = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NONE": 0,
}


def content_hash(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode()).hexdigest()


def is_ai_ml_relevant(cve: dict) -> bool:
    """Check if a CVE is relevant to AI/ML infrastructure."""
    descriptions = cve.get("descriptions", [])
    full_text = " ".join(
        d.get("value", "") for d in descriptions if d.get("lang") == "en"
    ).lower()

    # also check CPE configurations for AI/ML product names
    configs = cve.get("configurations", [])
    cpe_text = ""
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe_text += cpe_match.get("criteria", "").lower() + " "

    combined = full_text + " " + cpe_text
    return any(kw in combined for kw in AI_ML_KEYWORDS)


def extract_cvss_score(cve: dict) -> tuple[float | None, str | None]:
    """Extract CVSS base score and severity from metrics."""
    metrics = cve.get("metrics", {})

    # prefer CVSSv3.1 → CVSSv3.0 → CVSSv2
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            data = metric_list[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metric_list[0].get("baseSeverity")
            return score, severity

    return None, None


def extract_weakness(cve: dict) -> list[str]:
    """Extract CWE IDs from weaknesses."""
    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwes.append(value)
    return cwes


def extract_references(cve: dict) -> list[str]:
    """Extract reference URLs — useful for linking to PoC exploits."""
    refs = cve.get("references", [])
    return [r.get("url", "") for r in refs if r.get("url")]


def parse_cve_item(item: dict) -> dict | None:
    """Parse a single NVD CVE item into a normalized record."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # english description only
    descriptions = cve.get("descriptions", [])
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        ""
    )

    if not is_ai_ml_relevant(cve):
        return None

    cvss_score, severity = extract_cvss_score(cve)
    cwes = extract_weakness(cve)
    references = extract_references(cve)

    # parse dates
    published_raw = cve.get("published", "")
    modified_raw = cve.get("lastModified", "")

    try:
        published_utc = datetime.fromisoformat(
            published_raw.replace("Z", "+00:00")
        ).isoformat()
    except Exception:
        published_utc = None

    try:
        modified_utc = datetime.fromisoformat(
            modified_raw.replace("Z", "+00:00")
        ).isoformat()
    except Exception:
        modified_utc = None

    full_text = f"{cve_id} {description}"

    return {
        "source": "nvd_cve",
        "cve_id": cve_id,
        "description": description,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "cvss_score": cvss_score,
        "severity": severity,
        "severity_rank": SEVERITY_MAP.get(severity or "NONE", 0),
        "cwe_ids": cwes,
        "references": references[:5],       # cap at 5 refs per CVE
        "published_utc": published_utc,
        "modified_utc": modified_utc,
        "scraped_at": datetime.now(tz=timezone.utc).isoformat(),
        "content_hash": content_hash(full_text),
    }


def fetch_cves_by_date_range(
    start_date: datetime,
    end_date: datetime,
    results_per_page: int = 100,
) -> Generator[dict, None, None]:
    """
    Fetch CVEs from NVD within a date range.
    Paginates automatically using startIndex.
    """
    start_index = 0
    pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.999")

    while True:
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }

        try:
            resp = SESSION.get(NVD_BASE_URL, params=params, timeout=20)
            resp.raise_for_status()
            data = resp.json()

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            logger.info(
                f"NVD page {start_index // results_per_page + 1} — "
                f"{len(vulnerabilities)} CVEs "
                f"(total: {total_results})"
            )

            for item in vulnerabilities:
                record = parse_cve_item(item)
                if record:
                    yield record

            start_index += results_per_page
            if start_index >= total_results:
                break

            time.sleep(6)   # NVD rate limit: 5 requests per 30s without API key

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.warning("NVD rate limit hit — sleeping 30s...")
                time.sleep(30)
                continue
            logger.error(f"NVD HTTP error: {e}")
            break
        except Exception as e:
            logger.error(f"NVD fetch error: {e}")
            break


def fetch_recently_modified(days_back: int = 7) -> Generator[dict, None, None]:
    """
    Fetch CVEs modified in the last N days.
    Catches severity updates and newly added PoC references
    on older CVEs — important for threat signal freshness.
    """
    end_date = datetime.now(tz=timezone.utc)
    start_date = end_date - timedelta(days=days_back)

    params = {
        "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.999"),
        "resultsPerPage": 100,
        "startIndex": 0,
    }

    try:
        resp = SESSION.get(NVD_BASE_URL, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()

        for item in data.get("vulnerabilities", []):
            record = parse_cve_item(item)
            if record:
                yield record

        time.sleep(6)

    except Exception as e:
        logger.error(f"NVD modified fetch error: {e}")


def run(days_back: int = 30) -> list[dict]:
    all_records = []
    seen_hashes: set[str] = set()

    end_date = datetime.now(tz=timezone.utc)
    start_date = end_date - timedelta(days=days_back)

    # pass 1: newly published CVEs in date window
    logger.info(f"Fetching CVEs published last {days_back} days...")
    for record in fetch_cves_by_date_range(start_date, end_date):
        if record["content_hash"] in seen_hashes:
            continue
        seen_hashes.add(record["content_hash"])
        all_records.append(record)

    # pass 2: recently modified CVEs — catches severity upgrades + new PoC refs
    logger.info("Fetching recently modified CVEs (last 7 days)...")
    for record in fetch_recently_modified(days_back=7):
        if record["content_hash"] in seen_hashes:
            continue
        seen_hashes.add(record["content_hash"])
        all_records.append(record)

    # sort by severity descending before saving
    all_records.sort(key=lambda r: r.get("severity_rank", 0), reverse=True)

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = RAW_OUTPUT_DIR / f"cve_{timestamp}.json"
    with open(output_path, "w") as f:
        json.dump(all_records, f, indent=2)

    logger.info(f"Saved {len(all_records)} AI/ML CVEs → {output_path}")
    return all_records


if __name__ == "__main__":
    records = run(days_back=30)
    print(f"\nTotal AI/ML relevant CVEs scraped: {len(records)}")

    # print severity breakdown
    from collections import Counter
    severity_counts = Counter(r.get("severity", "UNKNOWN") for r in records)
    print("\nSeverity breakdown:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")