-- dbt/models/gold/gold_emerging_threats.sql
-- Signals with velocity spike in last 7 days — highest priority feed
{{ config(
    materialized = 'table',
    tags         = ['gold'],
) }}

WITH recent_signals AS (
    SELECT *
    FROM {{ ref('gold_threat_signals') }}
    WHERE signal_timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days'
),

spiking_categories AS (
    SELECT DISTINCT primary_category
    FROM {{ ref('silver_source_velocity') }}
    WHERE is_spike = TRUE
      AND signal_date >= CURRENT_DATE - INTERVAL '7 days'
)

SELECT
    r.*,
    TRUE                            AS is_emerging
FROM recent_signals r
INNER JOIN spiking_categories s
    ON r.primary_category = s.primary_category
ORDER BY r.severity_score DESC, r.signal_timestamp DESC