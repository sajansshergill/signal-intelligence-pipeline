-- dbt/models/bronze/bronze_arxiv_papers.sql
{{ config(
    materialized = 'incremental',
    unique_key   = 'content_hash',
    tags         = ['bronze', 'arxiv'],
) }}

SELECT
    content_hash,
    source,
    pipeline_source,
    schema_version,
    arxiv_id,
    title,
    abstract,
    url,
    pdf_url,
    author_count,
    categories,
    published_utc::TIMESTAMPTZ        AS published_utc,
    updated_utc::TIMESTAMPTZ          AS updated_utc,
    scraped_at::TIMESTAMPTZ           AS scraped_at,
    ingested_at::TIMESTAMPTZ          AS ingested_at,
    NOW()                             AS dbt_updated_at

FROM {{ source('threat_signals', 'raw_signals') }}

WHERE source = 'arxiv'
  AND content_hash IS NOT NULL
  AND abstract IS NOT NULL
  AND LENGTH(TRIM(abstract)) > 50

{% if is_incremental() %}
  AND ingested_at > (SELECT MAX(ingested_at) FROM {{ this }})
{% endif %}