-- dbt/models/silver/silver_source_velocity.sql
-- Daily signal volume per source — spike detection feed
{{ config(
    materialized = 'table',
    tags         = ['silver'],
) }}

WITH daily_counts AS (
    SELECT
        source,
        signal_type,
        primary_category,
        DATE_TRUNC('day', signal_timestamp)   AS signal_date,
        COUNT(*)                               AS signal_count,
        AVG(severity_score)                    AS avg_severity,
        MAX(severity_score)                    AS max_severity
    FROM {{ ref('silver_threat_signals') }}
    WHERE signal_timestamp IS NOT NULL
    GROUP BY 1, 2, 3, 4
),

with_rolling AS (
    SELECT
        *,
        AVG(signal_count) OVER (
            PARTITION BY source, primary_category
            ORDER BY signal_date
            ROWS BETWEEN 6 PRECEDING AND 1 PRECEDING
        )                                      AS rolling_7d_avg,

        LAG(signal_count, 1) OVER (
            PARTITION BY source, primary_category
            ORDER BY signal_date
        )                                      AS prev_day_count
    FROM daily_counts
)

SELECT
    *,
    CASE
        WHEN rolling_7d_avg IS NULL OR rolling_7d_avg = 0 THEN NULL
        ELSE ROUND(signal_count / rolling_7d_avg, 2)
    END                                        AS velocity_ratio,

    CASE
        WHEN rolling_7d_avg IS NULL OR rolling_7d_avg = 0 THEN FALSE
        WHEN signal_count / rolling_7d_avg >= 2.0 THEN TRUE
        ELSE FALSE
    END                                        AS is_spike
FROM with_rolling
ORDER BY signal_date DESC, signal_count DESC