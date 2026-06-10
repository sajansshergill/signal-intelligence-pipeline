-- dbt/models/silver/silver_entity_mentions.sql
-- Which model families + companies appear in threat discourse
{{ config(
    materialized = 'table',
    tags         = ['silver'],
) }}

WITH signals AS (
    SELECT
        content_hash,
        source,
        primary_category,
        severity_score,
        signal_timestamp,
        LOWER(COALESCE(title, '') || ' ' || COALESCE(body_text, '') || ' ' || COALESCE(abstract, '')) AS full_text
    FROM {{ ref('silver_threat_signals') }}
),

entity_flags AS (
    SELECT
        content_hash,
        source,
        primary_category,
        severity_score,
        signal_timestamp,

        -- LLM providers
        CASE WHEN full_text LIKE '%openai%' OR full_text LIKE '%chatgpt%' OR full_text LIKE '%gpt-4%' THEN 1 ELSE 0 END AS mentions_openai,
        CASE WHEN full_text LIKE '%anthropic%' OR full_text LIKE '%claude%' THEN 1 ELSE 0 END                           AS mentions_anthropic,
        CASE WHEN full_text LIKE '%google%' OR full_text LIKE '%gemini%' OR full_text LIKE '%bard%' THEN 1 ELSE 0 END   AS mentions_google,
        CASE WHEN full_text LIKE '%meta%' OR full_text LIKE '%llama%' THEN 1 ELSE 0 END                                 AS mentions_meta,
        CASE WHEN full_text LIKE '%mistral%' THEN 1 ELSE 0 END                                                          AS mentions_mistral,
        CASE WHEN full_text LIKE '%cohere%' THEN 1 ELSE 0 END                                                           AS mentions_cohere,

        -- ML frameworks
        CASE WHEN full_text LIKE '%pytorch%' THEN 1 ELSE 0 END                                                          AS mentions_pytorch,
        CASE WHEN full_text LIKE '%tensorflow%' THEN 1 ELSE 0 END                                                       AS mentions_tensorflow,
        CASE WHEN full_text LIKE '%hugging face%' OR full_text LIKE '%huggingface%' THEN 1 ELSE 0 END                   AS mentions_huggingface,

        -- infrastructure
        CASE WHEN full_text LIKE '%langchain%' THEN 1 ELSE 0 END                                                        AS mentions_langchain,
        CASE WHEN full_text LIKE '%mlflow%' THEN 1 ELSE 0 END                                                           AS mentions_mlflow,
        CASE WHEN full_text LIKE '%airflow%' THEN 1 ELSE 0 END                                                          AS mentions_airflow

    FROM signals
)

-- unpivot entity flags into rows for easier querying
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'openai'       AS entity, mentions_openai       AS is_mentioned FROM entity_flags WHERE mentions_openai       = 1
UNION ALL
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'anthropic'    AS entity, mentions_anthropic    AS is_mentioned FROM entity_flags WHERE mentions_anthropic    = 1
UNION ALL
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'google'       AS entity, mentions_google       AS is_mentioned FROM entity_flags WHERE mentions_google       = 1
UNION ALL
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'meta'         AS entity, mentions_meta         AS is_mentioned FROM entity_flags WHERE mentions_meta         = 1
UNION ALL
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'mistral'      AS entity, mentions_mistral      AS is_mentioned FROM entity_flags WHERE mentions_mistral      = 1
UNION ALL
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'pytorch'      AS entity, mentions_pytorch      AS is_mentioned FROM entity_flags WHERE mentions_pytorch      = 1
UNION ALL
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'tensorflow'   AS entity, mentions_tensorflow   AS is_mentioned FROM entity_flags WHERE mentions_tensorflow   = 1
UNION ALL
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'huggingface'  AS entity, mentions_huggingface  AS is_mentioned FROM entity_flags WHERE mentions_huggingface  = 1
UNION ALL
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'langchain'    AS entity, mentions_langchain    AS is_mentioned FROM entity_flags WHERE mentions_langchain    = 1
UNION ALL
SELECT content_hash, source, primary_category, severity_score, signal_timestamp,
    'mlflow'       AS entity, mentions_mlflow       AS is_mentioned FROM entity_flags WHERE mentions_mlflow       = 1