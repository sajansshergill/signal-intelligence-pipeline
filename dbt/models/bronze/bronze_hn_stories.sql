-- dbt/models/bronze/bronze_hn_stories.sql
{{ config(
    materialized = 'incremental',
    unique_key   = 'content_hash',
    tags         = ['bronze', 'hn'],
) }}

SELECT
    content_hash,
    source,
    pipeline_source,
    schema_version,
    item_id,
    title,
    body,
    url,
    score,
    num_comments,
    created_utc::TIMESTAMPTZ          AS created_utc,
    scraped_at::TIMESTAMPTZ           AS scraped_at,
    ingested_at::TIMESTAMPTZ          AS ingested_at,
    NOW()                             AS dbt_updated_at

FROM {{ source('threat_signals', 'raw_signals') }}

WHERE source IN ('hackernews', 'hackernews_algolia')
  AND content_hash IS NOT NULL
  AND (body IS NOT NULL OR title IS NOT NULL)

{% if is_incremental() %}
  AND ingested_at > (SELECT MAX(ingested_at) FROM {{ this }})
{% endif %}