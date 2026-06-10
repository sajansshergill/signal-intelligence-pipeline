-- dbt/models/gold/gold_threat_signals.sql
-- Final enriched intelligence table — served directly to API + dashboard
{{ config(
    materialized = 'incremental',
    unique_key   = 'content_hash',
    tags         = ['gold'],
    indexes      = [
        {'columns': ['content_hash'], 'unique': True},
        {'columns': ['severity_score']},
        {'columns': ['primary_category']},
        {'columns': ['signal_timestamp']},
    ]
) }}

SELECT
    -- identity
    s.content_hash,
    s.source,
    s.signal_type,

    -- content
    s.title,
    s.body_text,
    s.abstract,
    s.url,

    -- classification
    s.primary_category,
    s.threat_categories,
    s.severity_score,
    s.severity_band,
    s.severity_components,

    -- engagement
    s.engagement_score,
    s.comment_count,

    -- velocity context
    v.velocity_ratio,
    v.is_spike,
    v.rolling_7d_avg,

    -- timestamps
    s.signal_timestamp,
    s.scraped_at,
    s.processed_at,
    NOW()                           AS gold_updated_at

FROM {{ ref('silver_threat_signals') }} s

LEFT JOIN {{ ref('silver_source_velocity') }} v
    ON  s.source            = v.source
    AND s.primary_category  = v.primary_category
    AND DATE_TRUNC('day', s.signal_timestamp) = v.signal_date

WHERE s.severity_score IS NOT NULL
  AND s.severity_score > 0

{% if is_incremental() %}
  AND s.ingested_at > (SELECT MAX(ingested_at) FROM {{ ref('silver_threat_signals') }}
                       WHERE ingested_at <= (SELECT MAX(gold_updated_at) FROM {{ this }}))
{% endif %}

ORDER BY s.severity_score DESC