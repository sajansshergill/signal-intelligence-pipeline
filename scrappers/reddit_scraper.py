# scrapers/reddit_scraper.py

import praw
import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator
from dotenv import load_dotenv
import os

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SUBREDDITS = [
    "MachineLearning",
    "netsec",
    "ArtificialIntelligence",
    "AIAssistants",
    "LLMPromptEngineering",
    "ChatGPTJailbreak",
    "hacking",
    "cybersecurity",
]

THREAT_KEYWORDS = [
    "jailbreak", "prompt injection", "adversarial", "bypass", "exploit",
    "data poisoning", "model extraction", "backdoor", "fine-tune attack",
    "hallucination exploit", "RLHF", "jail break", "DAN", "do anything now",
    "content filter bypass", "unsafe output", "model stealing", "supply chain",
    "trojan", "malicious fine-tune", "red team", "alignment failure",
]

RAW_OUTPUT_DIR = Path("data/raw/reddit")
RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def build_reddit_client() -> praw.Reddit:
    return praw.Reddit(
        client_id=os.getenv("REDDIT_CLIENT_ID"),
        client_secret=os.getenv("REDDIT_CLIENT_SECRET"),
        user_agent=os.getenv("REDDIT_USER_AGENT", "ai-threat-pipeline/1.0"),
    )


def content_hash(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode()).hexdigest()


def is_relevant(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in THREAT_KEYWORDS)


def scrape_subreddit(
    reddit: praw.Reddit,
    subreddit_name: str,
    limit: int = 100,
) -> Generator[dict, None, None]:
    subreddit = reddit.subreddit(subreddit_name)

    for submission in subreddit.new(limit=limit):
        full_text = f"{submission.title} {submission.selftext}"
        if not is_relevant(full_text):
            continue

        record = {
            "source": "reddit",
            "subreddit": subreddit_name,
            "post_id": submission.id,
            "title": submission.title,
            "body": submission.selftext,
            "url": submission.url,
            "author": "[anonymized]",           # anonymized at scrape time
            "score": submission.score,
            "num_comments": submission.num_comments,
            "created_utc": datetime.fromtimestamp(
                submission.created_utc, tz=timezone.utc
            ).isoformat(),
            "scraped_at": datetime.now(tz=timezone.utc).isoformat(),
            "content_hash": content_hash(full_text),
        }
        yield record

    # scrape top comments from hot posts for deeper signal
    for submission in subreddit.hot(limit=50):
        submission.comments.replace_more(limit=0)
        for comment in submission.comments.list():
            if not is_relevant(comment.body):
                continue

            record = {
                "source": "reddit_comment",
                "subreddit": subreddit_name,
                "post_id": submission.id,
                "comment_id": comment.id,
                "title": submission.title,
                "body": comment.body,
                "url": f"https://reddit.com{comment.permalink}",
                "author": "[anonymized]",
                "score": comment.score,
                "num_comments": None,
                "created_utc": datetime.fromtimestamp(
                    comment.created_utc, tz=timezone.utc
                ).isoformat(),
                "scraped_at": datetime.now(tz=timezone.utc).isoformat(),
                "content_hash": content_hash(comment.body),
            }
            yield record


def run(limit: int = 100) -> list[dict]:
    reddit = build_reddit_client()
    all_records = []
    seen_hashes: set[str] = set()

    for subreddit_name in SUBREDDITS:
        logger.info(f"Scraping r/{subreddit_name}...")
        try:
            for record in scrape_subreddit(reddit, subreddit_name, limit=limit):
                if record["content_hash"] in seen_hashes:
                    logger.debug(f"Duplicate skipped: {record['content_hash'][:12]}")
                    continue
                seen_hashes.add(record["content_hash"])
                all_records.append(record)
        except Exception as e:
            logger.error(f"Failed scraping r/{subreddit_name}: {e}")
            continue

    # persist to raw landing zone
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = RAW_OUTPUT_DIR / f"reddit_{timestamp}.json"
    with open(output_path, "w") as f:
        json.dump(all_records, f, indent=2)

    logger.info(f"Saved {len(all_records)} records → {output_path}")
    return all_records


if __name__ == "__main__":
    records = run(limit=100)
    print(f"\nTotal relevant records scraped: {len(records)}")