-- dbt/models/bronze/bronze_reddit_posts.sql
-- config ---------------------------------------------------------------
{{ config(
    materialized = 'incremental',
    unique_key   = 'content_hash',
    tags         = ['bronze', 'reddit'],
    indexes      = [
        {'columns': ['content_hash'], 'unique': True},
        {'columns': ['ingested_at']},
        {'columns': ['source']},
    ]
) }}

SELECT
    content_hash,
    source,
    pipeline_source,
    schema_version,
    subreddit,
    post_id,
    comment_id,
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

WHERE source IN ('reddit', 'reddit_comment')
  AND content_hash IS NOT NULL
  AND body IS NOT NULL
  AND LENGTH(TRIM(body)) > 20

{% if is_incremental() %}
  AND ingested_at > (SELECT MAX(ingested_at) FROM {{ this }})
{% endif %}