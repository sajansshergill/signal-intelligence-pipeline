# dashboard/app.py

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import duckdb
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DUCKDB_PATH = "data/threat_signals.duckdb"

SEVERITY_COLORS = {
    "CRITICAL": "#d62728",
    "HIGH":     "#ff7f0e",
    "MEDIUM":   "#f0c419",
    "LOW":      "#2ca02c",
    "MINIMAL":  "#aec7e8",
}

CATEGORY_COLORS = {
    "jailbreak":          "#d62728",
    "prompt_injection":   "#ff7f0e",
    "supply_chain":       "#9467bd",
    "infrastructure":     "#8c564b",
    "policy_evasion":     "#e377c2",
    "data_poisoning":     "#bcbd22",
    "model_extraction":   "#17becf",
    "adversarial_inputs": "#1f77b4",
    "privacy_attack":     "#2ca02c",
    "alignment_failure":  "#7f7f7f",
    "unclassified":       "#c7c7c7",
}

# ---------------------------------------------------------------------------
# page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="AI Threat Signal Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# db connection — cached for session
# ---------------------------------------------------------------------------

def ensure_demo_database() -> None:
    """Create a small local DuckDB so the dashboard opens before ingestion runs."""
    db_path = Path(DUCKDB_PATH)
    if db_path.exists():
        return

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(db_path))
    now = datetime.now(tz=timezone.utc)
    rows = [
        (
            "demo-001", "hackernews", "social", "Prompt injection in RAG agent tools",
            "Researchers found indirect prompt injection in tool output.", None,
            "https://news.ycombinator.com/item?id=demo001", "prompt_injection",
            json.dumps(["prompt_injection", "privacy_attack"]), 8.4, "HIGH",
            json.dumps({"base": 7.0, "recency_boost": 0.8, "engagement_boost": 0.6}),
            184.0, 42, 2.6, True, 12.0,
            now - timedelta(days=1), now - timedelta(days=1), now, now,
        ),
        (
            "demo-002", "nvd_cve", "vulnerability", "CVE-2026-1001 TorchServe RCE",
            "Remote code execution in an ML serving stack.", None,
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1001", "infrastructure",
            json.dumps(["infrastructure", "supply_chain"]), 9.6, "CRITICAL",
            json.dumps({"base": 9.1, "exploit_reference_boost": 0.5}),
            960.0, 0, 1.8, False, 7.0,
            now - timedelta(days=2), now - timedelta(days=2), now, now,
        ),
        (
            "demo-003", "arxiv", "research", "Backdoor attacks against open model checkpoints",
            None, "A study of poisoned checkpoints and supply-chain risk.",
            "https://arxiv.org/abs/2606.00001", "supply_chain",
            json.dumps(["supply_chain", "data_poisoning"]), 7.9, "HIGH",
            json.dumps({"base": 8.0, "breadth_boost": 0.25}),
            0.0, 0, 2.2, True, 4.0,
            now - timedelta(days=3), now - timedelta(days=3), now, now,
        ),
        (
            "demo-004", "reddit", "social", "Jailbreak bypass report",
            "Users shared a new role-play jailbreak pattern.", None,
            "https://reddit.com/r/ChatGPTJailbreak/demo", "jailbreak",
            json.dumps(["jailbreak", "policy_evasion"]), 6.8, "MEDIUM",
            json.dumps({"base": 6.2, "engagement_boost": 0.6}),
            91.0, 27, 1.1, False, 5.0,
            now - timedelta(days=4), now - timedelta(days=4), now, now,
        ),
    ]

    conn.execute("""
        CREATE TABLE gold_threat_signals (
            content_hash VARCHAR,
            source VARCHAR,
            signal_type VARCHAR,
            title VARCHAR,
            body_text VARCHAR,
            abstract VARCHAR,
            url VARCHAR,
            primary_category VARCHAR,
            threat_categories VARCHAR,
            severity_score DOUBLE,
            severity_band VARCHAR,
            severity_components VARCHAR,
            engagement_score DOUBLE,
            comment_count INTEGER,
            velocity_ratio DOUBLE,
            is_spike BOOLEAN,
            rolling_7d_avg DOUBLE,
            signal_timestamp TIMESTAMPTZ,
            scraped_at TIMESTAMPTZ,
            processed_at TIMESTAMPTZ,
            gold_updated_at TIMESTAMPTZ
        )
    """)
    conn.executemany("""
        INSERT INTO gold_threat_signals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    conn.execute("""
        CREATE TABLE silver_source_velocity AS
        SELECT
            source,
            signal_type,
            primary_category,
            DATE_TRUNC('day', signal_timestamp) AS signal_date,
            COUNT(*) AS signal_count,
            AVG(severity_score) AS avg_severity,
            MAX(severity_score) AS max_severity,
            AVG(rolling_7d_avg) AS rolling_7d_avg,
            NULL::INTEGER AS prev_day_count,
            AVG(velocity_ratio) AS velocity_ratio,
            BOOL_OR(is_spike) AS is_spike
        FROM gold_threat_signals
        GROUP BY 1, 2, 3, 4
    """)

    conn.execute("""
        CREATE TABLE gold_emerging_threats AS
        SELECT *
        FROM gold_threat_signals
        WHERE is_spike = TRUE
    """)

    conn.execute("""
        CREATE TABLE gold_entity_risk_map (
            entity VARCHAR,
            primary_category VARCHAR,
            mention_count INTEGER,
            avg_severity DOUBLE,
            max_severity DOUBLE,
            high_severity_mentions INTEGER,
            source_diversity INTEGER,
            latest_mention_at TIMESTAMPTZ,
            computed_at TIMESTAMPTZ
        )
    """)
    conn.executemany("""
        INSERT INTO gold_entity_risk_map VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        ("gpt", "prompt_injection", 8, 8.1, 8.4, 8, 2, now - timedelta(days=1), now),
        ("torchserve", "infrastructure", 5, 9.6, 9.6, 5, 1, now - timedelta(days=2), now),
        ("huggingface", "supply_chain", 6, 7.9, 7.9, 6, 1, now - timedelta(days=3), now),
    ])
    conn.close()


@st.cache_resource
def get_connection() -> duckdb.DuckDBPyConnection:
    ensure_demo_database()
    return duckdb.connect(DUCKDB_PATH, read_only=True)


@st.cache_data(ttl=300)     # cache query results for 5 minutes
def query(_conn, sql: str, params: list = None) -> pd.DataFrame:
    try:
        if params:
            return _conn.execute(sql, params).fetchdf()
        return _conn.execute(sql).fetchdf()
    except Exception as e:
        logger.error(f"Query error: {e}\nSQL: {sql}")
        return pd.DataFrame()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def fmt_score(score) -> str:
    if score is None:
        return "—"
    return f"{float(score):.1f}"


def severity_badge(band: str) -> str:
    colors = {
        "CRITICAL": "🔴", "HIGH": "🟠",
        "MEDIUM": "🟡", "LOW": "🟢", "MINIMAL": "⚪"
    }
    return f"{colors.get(band, '⚪')} {band}"


def parse_categories(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    try:
        return json.loads(value)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# sidebar — filters
# ---------------------------------------------------------------------------

def render_sidebar(conn) -> dict:
    st.sidebar.image("https://img.shields.io/badge/AI%20Threat%20Intelligence-Pipeline-red", width=250)
    st.sidebar.markdown("---")
    st.sidebar.header("🔧 Filters")

    # severity filter
    severity_options = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]
    selected_severity = st.sidebar.selectbox("Severity Band", severity_options)

    # category filter
    category_options = [
        "All", "jailbreak", "prompt_injection", "data_poisoning",
        "model_extraction", "adversarial_inputs", "supply_chain",
        "infrastructure", "policy_evasion", "privacy_attack",
        "alignment_failure",
    ]
    selected_category = st.sidebar.selectbox("Threat Category", category_options)

    # source filter
    source_options = [
        "All", "reddit", "reddit_comment",
        "hackernews", "hackernews_algolia",
        "arxiv", "nvd_cve",
    ]
    selected_source = st.sidebar.selectbox("Data Source", source_options)

    # time range
    days_back = st.sidebar.slider(
        "Days back", min_value=1, max_value=90, value=30
    )

    # min severity score
    min_score = st.sidebar.slider(
        "Min severity score", min_value=0.0, max_value=10.0,
        value=0.0, step=0.5,
    )

    # spike only toggle
    spike_only = st.sidebar.checkbox("Emerging / spike signals only", value=False)

    st.sidebar.markdown("---")

    # pipeline health
    health = query(conn, """
        SELECT
            COUNT(*)                    AS total_signals,
            MAX(signal_timestamp)       AS latest_signal,
            MAX(processed_at)           AS latest_processed
        FROM gold_threat_signals
    """)

    if not health.empty:
        row = health.iloc[0]
        st.sidebar.metric("Total signals", int(row["total_signals"]))
        if row["latest_signal"]:
            st.sidebar.caption(f"Latest signal: {str(row['latest_signal'])[:16]}")
        if row["latest_processed"]:
            st.sidebar.caption(f"Last processed: {str(row['latest_processed'])[:16]}")

    return {
        "severity":  selected_severity,
        "category":  selected_category,
        "source":    selected_source,
        "days_back": days_back,
        "min_score": min_score,
        "spike_only": spike_only,
    }


# ---------------------------------------------------------------------------
# build filtered query
# ---------------------------------------------------------------------------

def build_filter_clause(filters: dict) -> tuple[str, list]:
    conditions = ["severity_score IS NOT NULL"]
    params = []

    if filters["severity"] != "All":
        conditions.append("severity_band = ?")
        params.append(filters["severity"])

    if filters["category"] != "All":
        conditions.append("primary_category = ?")
        params.append(filters["category"])

    if filters["source"] != "All":
        conditions.append("source = ?")
        params.append(filters["source"])

    if filters["min_score"] > 0:
        conditions.append("severity_score >= ?")
        params.append(filters["min_score"])

    if filters["spike_only"]:
        conditions.append("is_spike = TRUE")

    conditions.append(
        f"signal_timestamp >= CURRENT_TIMESTAMP - INTERVAL '{filters['days_back']} days'"
    )

    where = "WHERE " + " AND ".join(conditions)
    return where, params


# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------

def render_summary_cards(conn, filters: dict) -> None:
    where, params = build_filter_clause(filters)

    summary = query(conn, f"""
        SELECT
            COUNT(*)                                        AS total,
            COUNT(*) FILTER (WHERE severity_band='CRITICAL') AS critical,
            COUNT(*) FILTER (WHERE severity_band='HIGH')     AS high,
            COUNT(*) FILTER (WHERE is_spike = TRUE)          AS emerging,
            ROUND(AVG(severity_score), 2)                    AS avg_severity,
            COUNT(DISTINCT primary_category)                 AS categories_active
        FROM gold_threat_signals
        {where}
    """, params)

    if summary.empty:
        st.warning("No signals match current filters.")
        return

    r = summary.iloc[0]
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Signals",      int(r["total"]))
    c2.metric("🔴 Critical",        int(r["critical"]))
    c3.metric("🟠 High",            int(r["high"]))
    c4.metric("⚡ Emerging",        int(r["emerging"]))
    c5.metric("Avg Severity",       fmt_score(r["avg_severity"]))
    c6.metric("Active Categories",  int(r["categories_active"]))


def render_severity_distribution(conn, filters: dict) -> None:
    where, params = build_filter_clause(filters)

    df = query(conn, f"""
        SELECT severity_band, COUNT(*) AS count
        FROM gold_threat_signals
        {where}
        GROUP BY severity_band
        ORDER BY count DESC
    """, params)

    if df.empty:
        return

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Severity Distribution")
        fig = px.bar(
            df,
            x="severity_band",
            y="count",
            color="severity_band",
            color_discrete_map=SEVERITY_COLORS,
            labels={"severity_band": "Band", "count": "Signals"},
            text="count",
        )
        fig.update_layout(showlegend=False, height=320, margin=dict(t=20))
        fig.update_traces(textposition="outside")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Category Breakdown")
        cat_df = query(conn, f"""
            SELECT primary_category, COUNT(*) AS count
            FROM gold_threat_signals
            {where}
            GROUP BY primary_category
            ORDER BY count DESC
        """, params)

        if not cat_df.empty:
            fig2 = px.pie(
                cat_df,
                names="primary_category",
                values="count",
                color="primary_category",
                color_discrete_map=CATEGORY_COLORS,
                hole=0.4,
            )
            fig2.update_layout(height=320, margin=dict(t=20))
            st.plotly_chart(fig2, use_container_width=True)


def render_velocity_chart(conn, filters: dict) -> None:
    st.subheader("📈 Signal Velocity — Daily Volume with Spike Flags")

    df = query(conn, f"""
        SELECT
            signal_date,
            primary_category,
            signal_count,
            rolling_7d_avg,
            is_spike,
            velocity_ratio
        FROM silver_source_velocity
        WHERE signal_date >= CURRENT_DATE - INTERVAL '{filters['days_back']} days'
        ORDER BY signal_date ASC
    """)

    if df.empty:
        st.info("No velocity data available.")
        return

    # aggregate across categories for overall trend line
    daily_total = (
        df.groupby("signal_date")["signal_count"]
        .sum()
        .reset_index()
        .rename(columns={"signal_count": "total_signals"})
    )

    fig = go.Figure()

    # total volume bars
    fig.add_trace(go.Bar(
        x=daily_total["signal_date"],
        y=daily_total["total_signals"],
        name="Daily signals",
        marker_color="#1f77b4",
        opacity=0.7,
    ))

    # spike markers
    spikes = df[df["is_spike"] == True]
    if not spikes.empty:
        spike_totals = (
            spikes.groupby("signal_date")["signal_count"]
            .sum()
            .reset_index()
        )
        fig.add_trace(go.Scatter(
            x=spike_totals["signal_date"],
            y=spike_totals["signal_count"],
            mode="markers",
            name="⚡ Spike",
            marker=dict(color="#d62728", size=12, symbol="star"),
        ))

    fig.update_layout(
        height=350,
        margin=dict(t=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
        xaxis_title="Date",
        yaxis_title="Signal Count",
        barmode="overlay",
    )
    st.plotly_chart(fig, use_container_width=True)


def render_entity_risk_map(conn) -> None:
    st.subheader("🗺️ Entity Risk Map — Model Families in Threat Discourse")

    df = query(conn, """
        SELECT
            entity,
            SUM(mention_count)              AS total_mentions,
            ROUND(AVG(avg_severity), 2)     AS avg_severity,
            SUM(high_severity_mentions)     AS high_sev_mentions,
            COUNT(DISTINCT primary_category) AS threat_categories
        FROM gold_entity_risk_map
        GROUP BY entity
        ORDER BY avg_severity DESC
    """)

    if df.empty:
        st.info("No entity data available.")
        return

    fig = px.scatter(
        df,
        x="total_mentions",
        y="avg_severity",
        size="high_sev_mentions",
        color="avg_severity",
        text="entity",
        color_continuous_scale="Reds",
        labels={
            "total_mentions":    "Total Mentions",
            "avg_severity":      "Avg Severity Score",
            "high_sev_mentions": "High-Severity Mentions",
        },
        size_max=60,
    )
    fig.update_traces(textposition="top center")
    fig.update_layout(height=420, margin=dict(t=20))
    st.plotly_chart(fig, use_container_width=True)


def render_severity_heatmap(conn, filters: dict) -> None:
    st.subheader("🔥 Severity Heatmap — Category × Source")

    where, params = build_filter_clause(filters)

    df = query(conn, f"""
        SELECT
            primary_category,
            source,
            ROUND(AVG(severity_score), 2) AS avg_severity,
            COUNT(*) AS signal_count
        FROM gold_threat_signals
        {where}
        GROUP BY primary_category, source
    """, params)

    if df.empty:
        st.info("No data for heatmap.")
        return

    pivot = df.pivot_table(
        index="primary_category",
        columns="source",
        values="avg_severity",
        aggfunc="mean",
    ).fillna(0)

    fig = px.imshow(
        pivot,
        color_continuous_scale="Reds",
        aspect="auto",
        labels=dict(color="Avg Severity"),
        text_auto=".1f",
    )
    fig.update_layout(height=400, margin=dict(t=20))
    st.plotly_chart(fig, use_container_width=True)


def render_signal_table(conn, filters: dict) -> None:
    st.subheader("📋 Signal Feed")

    where, params = build_filter_clause(filters)

    df = query(conn, f"""
        SELECT
            severity_band,
            primary_category,
            source,
            title,
            severity_score,
            velocity_ratio,
            is_spike,
            signal_timestamp,
            url
        FROM gold_threat_signals
        {where}
        ORDER BY severity_score DESC
        LIMIT 200
    """, params)

    if df.empty:
        st.info("No signals match current filters.")
        return

    # format for display
    df["severity_band"]   = df["severity_band"].apply(severity_badge)
    df["severity_score"]  = df["severity_score"].apply(fmt_score)
    df["velocity_ratio"]  = df["velocity_ratio"].apply(
        lambda x: f"{x:.1f}×" if x else "—"
    )
    df["is_spike"]        = df["is_spike"].apply(lambda x: "⚡" if x else "")
    df["signal_timestamp"] = df["signal_timestamp"].apply(
        lambda x: str(x)[:16] if x else "—"
    )
    df["title"] = df["title"].apply(
        lambda x: (x[:100] + "…") if x and len(x) > 100 else (x or "—")
    )

    st.dataframe(
        df[[
            "severity_band", "is_spike", "primary_category",
            "source", "title", "severity_score",
            "velocity_ratio", "signal_timestamp",
        ]].rename(columns={
            "severity_band":    "Band",
            "is_spike":         "⚡",
            "primary_category": "Category",
            "source":           "Source",
            "title":            "Title",
            "severity_score":   "Score",
            "velocity_ratio":   "Velocity",
            "signal_timestamp": "Timestamp",
        }),
        use_container_width=True,
        height=500,
    )

    st.caption(f"Showing up to 200 signals. Use filters to narrow results.")


def render_emerging_threats(conn) -> None:
    st.subheader("⚡ Emerging Threats — Velocity Spikes Last 7 Days")

    df = query(conn, """
        SELECT
            primary_category,
            COUNT(*)                    AS signal_count,
            ROUND(AVG(severity_score), 2) AS avg_severity,
            ROUND(MAX(severity_score), 2) AS max_severity,
            MAX(signal_timestamp)       AS latest_signal
        FROM gold_emerging_threats
        GROUP BY primary_category
        ORDER BY avg_severity DESC
    """)

    if df.empty:
        st.success("No emerging threat spikes detected in the last 7 days.")
        return

    for _, row in df.iterrows():
        with st.expander(
            f"⚡ {row['primary_category'].upper()} "
            f"— {int(row['signal_count'])} signals "
            f"| avg severity {row['avg_severity']}"
        ):
            c1, c2, c3 = st.columns(3)
            c1.metric("Signal Count",  int(row["signal_count"]))
            c2.metric("Avg Severity",  fmt_score(row["avg_severity"]))
            c3.metric("Max Severity",  fmt_score(row["max_severity"]))
            st.caption(f"Latest: {str(row['latest_signal'])[:16]}")


# ---------------------------------------------------------------------------
# main layout
# ---------------------------------------------------------------------------

def main() -> None:
    conn = get_connection()
    filters = render_sidebar(conn)

    st.title("🛡️ AI Threat Signal Intelligence Pipeline")
    st.caption(
        "Adversarial AI threat signals scraped from Reddit, HackerNews, arXiv, and NVD CVE — "
        "classified, severity-scored, and enriched with velocity analytics."
    )
    st.markdown("---")

    # tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Overview",
        "⚡ Emerging Threats",
        "🗺️ Entity Risk Map",
        "📋 Signal Feed",
    ])

    with tab1:
        render_summary_cards(conn, filters)
        st.markdown("---")
        render_severity_distribution(conn, filters)
        st.markdown("---")
        render_velocity_chart(conn, filters)
        st.markdown("---")
        render_severity_heatmap(conn, filters)

    with tab2:
        render_emerging_threats(conn)

    with tab3:
        render_entity_risk_map(conn)

    with tab4:
        render_signal_table(conn, filters)

    # footer
    st.markdown("---")
    st.caption(
        f"Built by Sajan Singh Shergill · "
        f"Stack: Scrapy + Kafka + DuckDB + dbt + FastAPI + Streamlit · "
        f"Last refreshed: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )


if __name__ == "__main__":
    main()