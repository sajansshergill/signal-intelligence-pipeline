-- dbt/models/silver/silver_threat_signals.sql
-- Unified deduplicated + classified signal table across all sources
{{ config(
    materialized = 'incremental',
    unique_key   = 'content_hash',
    tags         = ['silver'],
) }}

WITH reddit AS (
    SELECT
        content_hash,
        source,
        'social'                          AS signal_type,
        title,
        body                              AS body_text,
        NULL                              AS abstract,
        url,
        score                             AS engagement_score,
        num_comments                      AS comment_count,
        created_utc                       AS signal_timestamp,
        scraped_at,
        ingested_at
    FROM {{ ref('bronze_reddit_posts') }}
),

hn AS (
    SELECT
        content_hash,
        source,
        'social'                          AS signal_type,
        title,
        body                              AS body_text,
        NULL                              AS abstract,
        url,
        score                             AS engagement_score,
        num_comments                      AS comment_count,
        created_utc                       AS signal_timestamp,
        scraped_at,
        ingested_at
    FROM {{ ref('bronze_hn_stories') }}
),

arxiv AS (
    SELECT
        content_hash,
        source,
        'research'                        AS signal_type,
        title,
        NULL                              AS body_text,
        abstract,
        url,
        0                                 AS engagement_score,
        0                                 AS comment_count,
        published_utc                     AS signal_timestamp,
        scraped_at,
        ingested_at
    FROM {{ ref('bronze_arxiv_papers') }}
),

cve AS (
    SELECT
        content_hash,
        source,
        'vulnerability'                   AS signal_type,
        cve_id                            AS title,
        description                       AS body_text,
        NULL                              AS abstract,
        url,
        COALESCE(cvss_score, 0) * 100     AS engagement_score,
        0                                 AS comment_count,
        published_utc                     AS signal_timestamp,
        scraped_at,
        ingested_at
    FROM {{ ref('bronze_cve_records') }}
),

unioned AS (
    SELECT * FROM reddit
    UNION ALL
    SELECT * FROM hn
    UNION ALL
    SELECT * FROM arxiv
    UNION ALL
    SELECT * FROM cve
),

-- join processed classification + severity scores from processed_signals
enriched AS (
    SELECT
        u.content_hash,
        u.source,
        u.signal_type,
        u.title,
        u.body_text,
        u.abstract,
        u.url,
        u.engagement_score,
        u.comment_count,
        u.signal_timestamp,
        u.scraped_at,
        u.ingested_at,
        p.primary_category,
        p.threat_categories,
        p.category_scores,
        p.severity_score,
        p.severity_band,
        p.severity_components,
        p.processed_at
    FROM unioned u
    LEFT JOIN {{ source('threat_signals', 'processed_signals') }} p
        ON u.content_hash = p.content_hash
)

SELECT *
FROM enriched
WHERE primary_category IS NOT NULL

{% if is_incremental() %}
  AND ingested_at > (SELECT MAX(ingested_at) FROM {{ this }})
{% endif %}