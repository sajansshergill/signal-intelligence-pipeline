# scrapers/hn_scraper.py

import requests
import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

HN_BASE_URL = "https://hacker-news.firebaseio.com/v0"
HN_SEARCH_URL = "https://hn.algolia.com/api/v1/search"

THREAT_KEYWORDS = [
    "jailbreak", "prompt injection", "adversarial", "bypass", "exploit",
    "data poisoning", "model extraction", "backdoor", "fine-tune attack",
    "hallucination exploit", "content filter bypass", "unsafe output",
    "model stealing", "supply chain", "trojan", "red team", "alignment failure",
    "llm attack", "ai safety", "model vulnerability", "rlhf exploit",
    "DAN", "do anything now", "ChatGPT bypass", "claude bypass",
]

RAW_OUTPUT_DIR = Path("data/raw/hn")
RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "ai-threat-pipeline/1.0"})


def content_hash(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode()).hexdigest()


def is_relevant(text: str) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    return any(kw in text_lower for kw in THREAT_KEYWORDS)


def fetch_item(item_id: int) -> dict | None:
    """Fetch a single HN item by ID."""
    try:
        resp = SESSION.get(f"{HN_BASE_URL}/item/{item_id}.json", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.debug(f"Failed to fetch item {item_id}: {e}")
        return None


def fetch_top_stories(limit: int = 200) -> list[int]:
    """Fetch top story IDs from HN Firebase API."""
    try:
        resp = SESSION.get(f"{HN_BASE_URL}/topstories.json", timeout=10)
        resp.raise_for_status()
        return resp.json()[:limit]
    except Exception as e:
        logger.error(f"Failed to fetch top stories: {e}")
        return []


def fetch_new_stories(limit: int = 200) -> list[int]:
    try:
        resp = SESSION.get(f"{HN_BASE_URL}/newstories.json", timeout=10)
        resp.raise_for_status()
        return resp.json()[:limit]
    except Exception as e:
        logger.error(f"Failed to fetch new stories: {e}")
        return []


def search_hn_algolia(keyword: str, limit: int = 20) -> list[dict]:
    """
    Use Algolia HN Search API for keyword-targeted retrieval.
    More precise than scanning all top/new stories.
    """
    try:
        params = {
            "query": keyword,
            "tags": "story",
            "hitsPerPage": limit,
        }
        resp = SESSION.get(HN_SEARCH_URL, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json().get("hits", [])
    except Exception as e:
        logger.error(f"Algolia search failed for '{keyword}': {e}")
        return []


def parse_story(item: dict) -> dict | None:
    """Parse a raw HN story item into a normalized record."""
    if not item or item.get("type") not in ("story", "comment"):
        return None

    title = item.get("title", "")
    text = item.get("text", "")
    url = item.get("url", "")
    full_text = f"{title} {text}"

    if not is_relevant(full_text):
        return None

    return {
        "source": "hackernews",
        "item_id": item.get("id"),
        "type": item.get("type"),
        "title": title,
        "body": text,
        "url": url or f"https://news.ycombinator.com/item?id={item.get('id')}",
        "author": "[anonymized]",
        "score": item.get("score", 0),
        "num_comments": item.get("descendants", 0),
        "created_utc": datetime.fromtimestamp(
            item.get("time", 0), tz=timezone.utc
        ).isoformat(),
        "scraped_at": datetime.now(tz=timezone.utc).isoformat(),
        "content_hash": content_hash(full_text),
    }


def parse_algolia_hit(hit: dict) -> dict | None:
    """Parse an Algolia search hit into a normalized record."""
    title = hit.get("title", "")
    text = hit.get("story_text") or hit.get("comment_text") or ""
    url = hit.get("url", "")
    full_text = f"{title} {text}"

    if not is_relevant(full_text):
        return None

    created_at = hit.get("created_at")
    try:
        created_utc = datetime.fromisoformat(created_at.replace("Z", "+00:00")).isoformat()
    except Exception:
        created_utc = None

    return {
        "source": "hackernews_algolia",
        "item_id": hit.get("objectID"),
        "type": hit.get("_tags", ["unknown"])[0],
        "title": title,
        "body": text,
        "url": url or f"https://news.ycombinator.com/item?id={hit.get('objectID')}",
        "author": "[anonymized]",
        "score": hit.get("points", 0),
        "num_comments": hit.get("num_comments", 0),
        "created_utc": created_utc,
        "scraped_at": datetime.now(tz=timezone.utc).isoformat(),
        "content_hash": content_hash(full_text),
    }


def scrape_firebase_feed(limit: int = 200) -> Generator[dict, None, None]:
    """Scan top + new stories via Firebase API."""
    story_ids = list(set(fetch_top_stories(limit) + fetch_new_stories(limit)))
    logger.info(f"Scanning {len(story_ids)} HN stories via Firebase...")

    for item_id in story_ids:
        item = fetch_item(item_id)
        if not item:
            continue
        record = parse_story(item)
        if record:
            yield record


def scrape_algolia_keywords() -> Generator[dict, None, None]:
    """Keyword-targeted search via Algolia — higher precision."""
    # use a subset of high-signal keywords to avoid rate limiting
    priority_keywords = [
        "jailbreak LLM",
        "prompt injection",
        "AI safety exploit",
        "model extraction attack",
        "adversarial AI",
        "LLM vulnerability",
        "ChatGPT bypass",
    ]

    seen_ids: set = set()
    for keyword in priority_keywords:
        logger.info(f"Algolia search: '{keyword}'")
        hits = search_hn_algolia(keyword, limit=20)
        for hit in hits:
            item_id = hit.get("objectID")
            if item_id in seen_ids:
                continue
            seen_ids.add(item_id)
            record = parse_algolia_hit(hit)
            if record:
                yield record


def run(firebase_limit: int = 200) -> list[dict]:
    all_records = []
    seen_hashes: set[str] = set()

    # pass 1: broad Firebase feed scan
    for record in scrape_firebase_feed(limit=firebase_limit):
        if record["content_hash"] in seen_hashes:
            continue
        seen_hashes.add(record["content_hash"])
        all_records.append(record)

    # pass 2: precision Algolia keyword search
    for record in scrape_algolia_keywords():
        if record["content_hash"] in seen_hashes:
            continue
        seen_hashes.add(record["content_hash"])
        all_records.append(record)

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = RAW_OUTPUT_DIR / f"hn_{timestamp}.json"
    with open(output_path, "w") as f:
        json.dump(all_records, f, indent=2)

    logger.info(f"Saved {len(all_records)} records → {output_path}")
    return all_records


if __name__ == "__main__":
    records = run(firebase_limit=200)
    print(f"\nTotal relevant HN records scraped: {len(records)}")