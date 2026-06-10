-- dbt/models/gold/gold_severity_index.sql
-- Aggregated severity by category — used for dashboard summary cards
{{ config(
    materialized = 'table',
    tags         = ['gold'],
) }}

SELECT
    primary_category,
    signal_type,
    COUNT(*)                                AS total_signals,
    ROUND(AVG(severity_score), 2)           AS avg_severity,
    ROUND(MAX(severity_score), 2)           AS max_severity,
    ROUND(PERCENTILE_CONT(0.95)
        WITHIN GROUP (ORDER BY severity_score), 2)
                                            AS p95_severity,
    COUNT(*) FILTER (WHERE severity_band = 'CRITICAL')  AS critical_count,
    COUNT(*) FILTER (WHERE severity_band = 'HIGH')      AS high_count,
    COUNT(*) FILTER (WHERE severity_band = 'MEDIUM')    AS medium_count,
    COUNT(*) FILTER (WHERE is_spike = TRUE)             AS spike_count,
    MAX(signal_timestamp)                   AS latest_signal_at,
    NOW()                                   AS computed_at

FROM {{ ref('gold_threat_signals') }}
GROUP BY 1, 2
ORDER BY avg_severity DESC