-- dbt/models/gold/gold_entity_risk_map.sql
-- Which entities appear most in high-severity adversarial discourse
{{ config(
    materialized = 'table',
    tags         = ['gold'],
) }}

SELECT
    e.entity,
    e.primary_category,
    COUNT(*)                                AS mention_count,
    ROUND(AVG(e.severity_score), 2)         AS avg_severity,
    ROUND(MAX(e.severity_score), 2)         AS max_severity,
    COUNT(*) FILTER (
        WHERE e.severity_score >= 6.0
    )                                       AS high_severity_mentions,
    COUNT(DISTINCT e.source)                AS source_diversity,
    MAX(e.signal_timestamp)                 AS latest_mention_at,
    NOW()                                   AS computed_at

FROM {{ ref('silver_entity_mentions') }} e
GROUP BY 1, 2
HAVING COUNT(*) >= 2
ORDER BY avg_severity DESC, mention_count DESC