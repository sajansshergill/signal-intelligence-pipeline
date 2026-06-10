-- dbt/models/bronze/bronze_cve_records.sql
{{ config(
    materialized = 'incremental',
    unique_key   = 'content_hash',
    tags         = ['bronze', 'cve'],
) }}

SELECT
    content_hash,
    source,
    pipeline_source,
    schema_version,
    cve_id,
    description,
    url,
    cvss_score,
    severity,
    severity_rank,
    cwe_ids,
    references,
    published_utc::TIMESTAMPTZ        AS published_utc,
    modified_utc::TIMESTAMPTZ         AS modified_utc,
    scraped_at::TIMESTAMPTZ           AS scraped_at,
    ingested_at::TIMESTAMPTZ          AS ingested_at,
    NOW()                             AS dbt_updated_at

FROM {{ source('threat_signals', 'raw_signals') }}

WHERE source = 'nvd_cve'
  AND content_hash IS NOT NULL
  AND description IS NOT NULL
  AND cve_id IS NOT NULL

{% if is_incremental() %}
  AND ingested_at > (SELECT MAX(ingested_at) FROM {{ this }})
{% endif %}