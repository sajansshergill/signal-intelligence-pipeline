# api/main.py

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import duckdb
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DUCKDB_PATH = "data/threat_signals.duckdb"

# ---------------------------------------------------------------------------
# pydantic response models
# ---------------------------------------------------------------------------

class ThreatSignal(BaseModel):
    content_hash:       str
    source:             str
    signal_type:        Optional[str]
    title:              Optional[str]
    body_text:          Optional[str]
    abstract:           Optional[str]
    url:                Optional[str]
    primary_category:   Optional[str]
    threat_categories:  Optional[list[str]]
    severity_score:     Optional[float]
    severity_band:      Optional[str]
    engagement_score:   Optional[float]
    comment_count:      Optional[int]
    velocity_ratio:     Optional[float]
    is_spike:           Optional[bool]
    signal_timestamp:   Optional[str]
    processed_at:       Optional[str]


class SeverityIndexRow(BaseModel):
    primary_category:       str
    signal_type:            Optional[str]
    total_signals:          int
    avg_severity:           float
    max_severity:           float
    p95_severity:           Optional[float]
    critical_count:         int
    high_count:             int
    medium_count:           int
    spike_count:            int
    latest_signal_at:       Optional[str]


class EntityRiskRow(BaseModel):
    entity:                 str
    primary_category:       str
    mention_count:          int
    avg_severity:           float
    max_severity:           float
    high_severity_mentions: int
    source_diversity:       int
    latest_mention_at:      Optional[str]


class HealthResponse(BaseModel):
    status:             str
    duckdb_path:        str
    gold_signal_count:  int
    last_ingested_at:   Optional[str]
    last_processed_at:  Optional[str]
    checked_at:         str


class PaginatedResponse(BaseModel):
    total:      int
    limit:      int
    offset:     int
    data:       list


# ---------------------------------------------------------------------------
# db connection pool (simple — DuckDB is single-writer, multi-reader safe)
# ---------------------------------------------------------------------------

_conn: duckdb.DuckDBPyConnection | None = None


def get_conn() -> duckdb.DuckDBPyConnection:
    global _conn
    if _conn is None:
        _conn = duckdb.connect(DUCKDB_PATH, read_only=True)
    return _conn


def close_conn() -> None:
    global _conn
    if _conn:
        _conn.close()
        _conn = None


# ---------------------------------------------------------------------------
# lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Connecting to DuckDB: {DUCKDB_PATH}")
    get_conn()
    yield
    logger.info("Closing DuckDB connection")
    close_conn()


# ---------------------------------------------------------------------------
# app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Threat Signal Intelligence API",
    description=(
        "REST API serving adversarial AI threat signals scraped from Reddit, "
        "HackerNews, arXiv, and NVD CVE — classified, severity-scored, and "
        "enriched with velocity analytics."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def parse_threat_categories(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    try:
        return json.loads(value)
    except Exception:
        return []


def row_to_signal(row: dict) -> ThreatSignal:
    return ThreatSignal(
        content_hash=       row.get("content_hash"),
        source=             row.get("source"),
        signal_type=        row.get("signal_type"),
        title=              row.get("title"),
        body_text=          row.get("body_text"),
        abstract=           row.get("abstract"),
        url=                row.get("url"),
        primary_category=   row.get("primary_category"),
        threat_categories=  parse_threat_categories(row.get("threat_categories")),
        severity_score=     row.get("severity_score"),
        severity_band=      row.get("severity_band"),
        engagement_score=   row.get("engagement_score"),
        comment_count=      row.get("comment_count"),
        velocity_ratio=     row.get("velocity_ratio"),
        is_spike=           row.get("is_spike"),
        signal_timestamp=   str(row["signal_timestamp"]) if row.get("signal_timestamp") else None,
        processed_at=       str(row["processed_at"]) if row.get("processed_at") else None,
    )


VALID_CATEGORIES = {
    "jailbreak", "prompt_injection", "data_poisoning", "model_extraction",
    "adversarial_inputs", "supply_chain", "infrastructure", "policy_evasion",
    "privacy_attack", "alignment_failure", "unclassified",
}

VALID_BANDS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"}
VALID_SOURCES = {"reddit", "reddit_comment", "hackernews", "hackernews_algolia", "arxiv", "nvd_cve"}


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["meta"])
def health_check(conn: duckdb.DuckDBPyConnection = Depends(get_conn)):
    """Pipeline health check — last run timestamps and record counts."""
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM gold_threat_signals"
        ).fetchone()[0]

        last_ingested = conn.execute(
            "SELECT MAX(ingested_at) FROM raw_signals"
        ).fetchone()[0]

        last_processed = conn.execute(
            "SELECT MAX(processed_at) FROM gold_threat_signals"
        ).fetchone()[0]

        return HealthResponse(
            status="healthy",
            duckdb_path=DUCKDB_PATH,
            gold_signal_count=count,
            last_ingested_at=str(last_ingested) if last_ingested else None,
            last_processed_at=str(last_processed) if last_processed else None,
            checked_at=datetime.now(tz=timezone.utc).isoformat(),
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Database error: {e}")


@app.get("/threats/latest", response_model=PaginatedResponse, tags=["threats"])
def get_latest_threats(
    limit:  int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    conn:   duckdb.DuckDBPyConnection = Depends(get_conn),
):
    """Most recent threat signals ordered by signal timestamp descending."""
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM gold_threat_signals"
        ).fetchone()[0]

        rows = conn.execute("""
            SELECT *
            FROM gold_threat_signals
            ORDER BY signal_timestamp DESC
            LIMIT ? OFFSET ?
        """, [limit, offset]).fetchdf().to_dict(orient="records")

        return PaginatedResponse(
            total=total,
            limit=limit,
            offset=offset,
            data=[row_to_signal(r).model_dump() for r in rows],
        )
    except Exception as e:
        logger.error(f"/threats/latest error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threats/severity", response_model=PaginatedResponse, tags=["threats"])
def get_threats_by_severity(
    band:   Optional[str] = Query(default=None, description="CRITICAL | HIGH | MEDIUM | LOW | MINIMAL"),
    limit:  int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    conn:   duckdb.DuckDBPyConnection = Depends(get_conn),
):
    """Signals ordered by severity score descending, optionally filtered by band."""
    if band and band.upper() not in VALID_BANDS:
        raise HTTPException(status_code=400, detail=f"Invalid band. Choose from: {VALID_BANDS}")

    try:
        where = f"WHERE severity_band = '{band.upper()}'" if band else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM gold_threat_signals {where}"
        ).fetchone()[0]

        rows = conn.execute(f"""
            SELECT *
            FROM gold_threat_signals
            {where}
            ORDER BY severity_score DESC
            LIMIT ? OFFSET ?
        """, [limit, offset]).fetchdf().to_dict(orient="records")

        return PaginatedResponse(
            total=total,
            limit=limit,
            offset=offset,
            data=[row_to_signal(r).model_dump() for r in rows],
        )
    except Exception as e:
        logger.error(f"/threats/severity error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threats/{category}", response_model=PaginatedResponse, tags=["threats"])
def get_threats_by_category(
    category:   str,
    limit:      int = Query(default=50, ge=1, le=500),
    offset:     int = Query(default=0, ge=0),
    min_severity: float = Query(default=0.0, ge=0.0, le=10.0),
    conn:       duckdb.DuckDBPyConnection = Depends(get_conn),
):
    """Signals filtered by threat category, ordered by severity descending."""
    if category not in VALID_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category. Valid options: {sorted(VALID_CATEGORIES)}"
        )

    try:
        total = conn.execute("""
            SELECT COUNT(*)
            FROM gold_threat_signals
            WHERE primary_category = ?
              AND severity_score >= ?
        """, [category, min_severity]).fetchone()[0]

        rows = conn.execute("""
            SELECT *
            FROM gold_threat_signals
            WHERE primary_category = ?
              AND severity_score >= ?
            ORDER BY severity_score DESC
            LIMIT ? OFFSET ?
        """, [category, min_severity, limit, offset]).fetchdf().to_dict(orient="records")

        return PaginatedResponse(
            total=total,
            limit=limit,
            offset=offset,
            data=[row_to_signal(r).model_dump() for r in rows],
        )
    except Exception as e:
        logger.error(f"/threats/{category} error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threats/emerging", response_model=PaginatedResponse, tags=["threats"])
def get_emerging_threats(
    limit:  int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    conn:   duckdb.DuckDBPyConnection = Depends(get_conn),
):
    """Signals from categories with velocity spike in the last 7 days."""
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM gold_emerging_threats"
        ).fetchone()[0]

        rows = conn.execute("""
            SELECT *
            FROM gold_emerging_threats
            ORDER BY severity_score DESC, signal_timestamp DESC
            LIMIT ? OFFSET ?
        """, [limit, offset]).fetchdf().to_dict(orient="records")

        return PaginatedResponse(
            total=total,
            limit=limit,
            offset=offset,
            data=[row_to_signal(r).model_dump() for r in rows],
        )
    except Exception as e:
        logger.error(f"/threats/emerging error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threats/source/{source}", response_model=PaginatedResponse, tags=["threats"])
def get_threats_by_source(
    source: str,
    limit:  int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    conn:   duckdb.DuckDBPyConnection = Depends(get_conn),
):
    """Signals filtered by data source."""
    if source not in VALID_SOURCES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source. Valid options: {sorted(VALID_SOURCES)}"
        )

    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM gold_threat_signals WHERE source = ?",
            [source]
        ).fetchone()[0]

        rows = conn.execute("""
            SELECT *
            FROM gold_threat_signals
            WHERE source = ?
            ORDER BY severity_score DESC
            LIMIT ? OFFSET ?
        """, [source, limit, offset]).fetchdf().to_dict(orient="records")

        return PaginatedResponse(
            total=total,
            limit=limit,
            offset=offset,
            data=[row_to_signal(r).model_dump() for r in rows],
        )
    except Exception as e:
        logger.error(f"/threats/source/{source} error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/entities", response_model=list[EntityRiskRow], tags=["entities"])
def get_entity_risk_map(
    min_mentions: int = Query(default=2, ge=1),
    conn: duckdb.DuckDBPyConnection = Depends(get_conn),
):
    """Entity risk map — which model families appear most in threat discourse."""
    try:
        rows = conn.execute("""
            SELECT *
            FROM gold_entity_risk_map
            WHERE mention_count >= ?
            ORDER BY avg_severity DESC, mention_count DESC
        """, [min_mentions]).fetchdf().to_dict(orient="records")

        return [
            EntityRiskRow(
                entity=             r["entity"],
                primary_category=   r["primary_category"],
                mention_count=      r["mention_count"],
                avg_severity=       r["avg_severity"],
                max_severity=       r["max_severity"],
                high_severity_mentions= r["high_severity_mentions"],
                source_diversity=   r["source_diversity"],
                latest_mention_at=  str(r["latest_mention_at"]) if r.get("latest_mention_at") else None,
            )
            for r in rows
        ]
    except Exception as e:
        logger.error(f"/entities error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/entities/{entity}", response_model=PaginatedResponse, tags=["entities"])
def get_signals_by_entity(
    entity: str,
    limit:  int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    conn:   duckdb.DuckDBPyConnection = Depends(get_conn),
):
    """All threat signals mentioning a specific model or company."""
    try:
        total = conn.execute("""
            SELECT COUNT(DISTINCT g.content_hash)
            FROM gold_threat_signals g
            INNER JOIN silver_entity_mentions e ON g.content_hash = e.content_hash
            WHERE e.entity = ?
        """, [entity.lower()]).fetchone()[0]

        rows = conn.execute("""
            SELECT g.*
            FROM gold_threat_signals g
            INNER JOIN silver_entity_mentions e ON g.content_hash = e.content_hash
            WHERE e.entity = ?
            ORDER BY g.severity_score DESC
            LIMIT ? OFFSET ?
        """, [entity.lower(), limit, offset]).fetchdf().to_dict(orient="records")

        return PaginatedResponse(
            total=total,
            limit=limit,
            offset=offset,
            data=[row_to_signal(r).model_dump() for r in rows],
        )
    except Exception as e:
        logger.error(f"/entities/{entity} error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/severity-index", response_model=list[SeverityIndexRow], tags=["analytics"])
def get_severity_index(
    conn: duckdb.DuckDBPyConnection = Depends(get_conn),
):
    """Aggregated severity by threat category — used for dashboard summary cards."""
    try:
        rows = conn.execute("""
            SELECT *
            FROM gold_severity_index
            ORDER BY avg_severity DESC
        """).fetchdf().to_dict(orient="records")

        return [
            SeverityIndexRow(
                primary_category=   r["primary_category"],
                signal_type=        r.get("signal_type"),
                total_signals=      r["total_signals"],
                avg_severity=       r["avg_severity"],
                max_severity=       r["max_severity"],
                p95_severity=       r.get("p95_severity"),
                critical_count=     r["critical_count"],
                high_count=         r["high_count"],
                medium_count=       r["medium_count"],
                spike_count=        r["spike_count"],
                latest_signal_at=   str(r["latest_signal_at"]) if r.get("latest_signal_at") else None,
            )
            for r in rows
        ]
    except Exception as e:
        logger.error(f"/severity-index error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/velocity", tags=["analytics"])
def get_velocity(
    days:   int = Query(default=7, ge=1, le=90),
    conn:   duckdb.DuckDBPyConnection = Depends(get_conn),
):
    """Source velocity — daily signal counts with spike flags for last N days."""
    try:
        rows = conn.execute("""
            SELECT *
            FROM silver_source_velocity
            WHERE signal_date >= CURRENT_DATE - INTERVAL (? || ' days')
            ORDER BY signal_date DESC, signal_count DESC
        """, [days]).fetchdf().to_dict(orient="records")

        return JSONResponse(content={
            "days":  days,
            "rows":  [
                {**r, "signal_date": str(r["signal_date"])}
                for r in rows
            ]
        })
    except Exception as e:
        logger.error(f"/velocity error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)