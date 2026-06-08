# scrapers/arxiv_scraper.py

import requests
import feedparser
import json
import hashlib
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ARXIV_BASE_URL = "http://export.arxiv.org/api/query"

RAW_OUTPUT_DIR = Path("data/raw/arxiv")
RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "ai-threat-pipeline/1.0"})

# arxiv search queries — structured for their API query syntax
SEARCH_QUERIES = [
    "adversarial attacks large language models",
    "jailbreak language models",
    "prompt injection attacks",
    "backdoor attacks neural networks",
    "model extraction attacks",
    "data poisoning machine learning",
    "AI safety red teaming",
    "supply chain attacks machine learning",
    "alignment failure language models",
    "reward hacking reinforcement learning",
    "trojan attacks deep learning",
    "membership inference attacks",
    "model inversion attacks privacy",
    "evasion attacks adversarial examples",
]

# categories most likely to contain threat-relevant papers
ARXIV_CATEGORIES = [
    "cs.CR",   # cryptography and security
    "cs.LG",   # machine learning
    "cs.AI",   # artificial intelligence
    "cs.CL",   # computation and language
    "stat.ML", # statistics machine learning
]

THREAT_KEYWORDS = [
    "jailbreak", "prompt injection", "adversarial", "backdoor", "poisoning",
    "extraction", "inversion", "evasion", "trojan", "red team", "bypass",
    "vulnerability", "attack", "exploit", "unsafe", "misuse", "harmful",
    "alignment", "reward hacking", "membership inference", "supply chain",
]


def content_hash(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode()).hexdigest()


def is_relevant(text: str) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    return any(kw in text_lower for kw in THREAT_KEYWORDS)


def parse_arxiv_entry(entry: dict) -> dict | None:
    """Parse a single feedparser entry into a normalized record."""
    title = entry.get("title", "").replace("\n", " ").strip()
    abstract = entry.get("summary", "").replace("\n", " ").strip()
    full_text = f"{title} {abstract}"

    if not is_relevant(full_text):
        return None

    # extract arxiv ID from the entry id URL
    arxiv_id = entry.get("id", "").split("/abs/")[-1]

    # extract authors — anonymized to count only
    authors = entry.get("authors", [])
    author_count = len(authors)

    # extract categories
    tags = entry.get("tags", [])
    categories = [t.get("term", "") for t in tags]

    # parse published date
    published_raw = entry.get("published", "")
    try:
        published_utc = datetime.strptime(
            published_raw, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        published_utc = None

    updated_raw = entry.get("updated", "")
    try:
        updated_utc = datetime.strptime(
            updated_raw, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        updated_utc = None

    # extract PDF link
    pdf_url = None
    for link in entry.get("links", []):
        if link.get("type") == "application/pdf":
            pdf_url = link.get("href")
            break

    return {
        "source": "arxiv",
        "arxiv_id": arxiv_id,
        "title": title,
        "abstract": abstract,
        "url": f"https://arxiv.org/abs/{arxiv_id}",
        "pdf_url": pdf_url,
        "author_count": author_count,       # anonymized — count only, no names
        "categories": categories,
        "published_utc": published_utc,
        "updated_utc": updated_utc,
        "scraped_at": datetime.now(tz=timezone.utc).isoformat(),
        "content_hash": content_hash(full_text),
    }


def fetch_arxiv_query(
    query: str,
    max_results: int = 50,
    sort_by: str = "submittedDate",
) -> Generator[dict, None, None]:
    """
    Fetch papers from arXiv API for a given search query.
    Paginates automatically if max_results > 100.
    """
    start = 0
    page_size = min(max_results, 100)   # arxiv API max per request is 100

    while start < max_results:
        params = {
            "search_query": f"all:{query}",
            "start": start,
            "max_results": page_size,
            "sortBy": sort_by,
            "sortOrder": "descending",
        }

        try:
            resp = SESSION.get(ARXIV_BASE_URL, params=params, timeout=15)
            resp.raise_for_status()
            feed = feedparser.parse(resp.text)
            entries = feed.get("entries", [])

            if not entries:
                logger.debug(f"No more results for query: '{query}' at start={start}")
                break

            for entry in entries:
                record = parse_arxiv_entry(entry)
                if record:
                    yield record

            start += page_size
            time.sleep(3)   # arxiv API rate limit: 3s between requests

        except Exception as e:
            logger.error(f"arXiv API error for query '{query}': {e}")
            break


def fetch_arxiv_by_category(
    category: str,
    max_results: int = 50,
) -> Generator[dict, None, None]:
    """
    Fetch recent papers from a specific arXiv category.
    Complements keyword search with category-level coverage.
    """
    params = {
        "search_query": f"cat:{category}",
        "start": 0,
        "max_results": max_results,
        "sortBy": "submittedDate",
        "sortOrder": "descending",
    }

    try:
        resp = SESSION.get(ARXIV_BASE_URL, params=params, timeout=15)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)

        for entry in feed.get("entries", []):
            record = parse_arxiv_entry(entry)
            if record:
                yield record

        time.sleep(3)

    except Exception as e:
        logger.error(f"arXiv category fetch error for '{category}': {e}")


def run(max_results_per_query: int = 50) -> list[dict]:
    all_records = []
    seen_hashes: set[str] = set()

    # pass 1: keyword-targeted queries
    for query in SEARCH_QUERIES:
        logger.info(f"arXiv query: '{query}'")
        for record in fetch_arxiv_query(query, max_results=max_results_per_query):
            if record["content_hash"] in seen_hashes:
                logger.debug(f"Duplicate skipped: {record['content_hash'][:12]}")
                continue
            seen_hashes.add(record["content_hash"])
            all_records.append(record)

    # pass 2: category-level sweep for cs.CR (security) — catches papers
    # that use different terminology but are still threat-relevant
    logger.info("arXiv category sweep: cs.CR")
    for record in fetch_arxiv_by_category("cs.CR", max_results=100):
        if record["content_hash"] in seen_hashes:
            continue
        seen_hashes.add(record["content_hash"])
        all_records.append(record)

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = RAW_OUTPUT_DIR / f"arxiv_{timestamp}.json"
    with open(output_path, "w") as f:
        json.dump(all_records, f, indent=2)

    logger.info(f"Saved {len(all_records)} records → {output_path}")
    return all_records


if __name__ == "__main__":
    records = run(max_results_per_query=50)
    print(f"\nTotal relevant arXiv records scraped: {len(records)}")