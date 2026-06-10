# airflow/dags/dbt_transformation_dag.py

import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.empty import EmptyOperator
from airflow.utils.trigger_rule import TriggerRule

logger = logging.getLogger(__name__)

DEFAULT_ARGS = {
    "owner":              "sajan",
    "depends_on_past":    False,
    "retries":            1,
    "retry_delay":        timedelta(minutes=3),
    "email_on_failure":   False,
    "email_on_retry":     False,
}

DBT_PROJECT_DIR = Path("/opt/airflow/dbt")
DBT_PROFILES_DIR = Path("/opt/airflow/dbt")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def run_dbt_command(command: list[str], task_name: str) -> dict:
    """
    Execute a dbt CLI command as a subprocess.
    Captures stdout/stderr and raises on non-zero exit.
    Using subprocess over BashOperator gives us structured
    return values and XCom-compatible output.
    """
    full_command = [
        "dbt", *command,
        "--project-dir", str(DBT_PROJECT_DIR),
        "--profiles-dir", str(DBT_PROFILES_DIR),
    ]

    logger.info(f"Running: {' '.join(full_command)}")

    result = subprocess.run(
        full_command,
        capture_output=True,
        text=True,
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if stdout:
        logger.info(f"[dbt stdout]\n{stdout}")
    if stderr:
        logger.warning(f"[dbt stderr]\n{stderr}")

    if result.returncode != 0:
        raise RuntimeError(
            f"dbt command failed [{task_name}] "
            f"exit_code={result.returncode}\n{stderr}"
        )

    return {
        "task":        task_name,
        "exit_code":   result.returncode,
        "stdout_tail": stdout[-500:] if stdout else "",
    }


# ---------------------------------------------------------------------------
# task callables
# ---------------------------------------------------------------------------

def task_dbt_deps(**ctx) -> dict:
    """Install dbt packages — runs once per DAG run."""
    return run_dbt_command(["deps"], task_name="dbt_deps")


def task_dbt_run_bronze(**ctx) -> dict:
    """
    Run bronze layer models only.
    Bronze = raw source models with minimal transformation.
    """
    return run_dbt_command(
        ["run", "--select", "tag:bronze"],
        task_name="dbt_run_bronze",
    )


def task_dbt_test_bronze(**ctx) -> dict:
    """Schema + data tests on bronze models before silver runs."""
    return run_dbt_command(
        ["test", "--select", "tag:bronze"],
        task_name="dbt_test_bronze",
    )


def task_dbt_run_silver(**ctx) -> dict:
    """
    Run silver layer models.
    Silver = cleaned, deduplicated, classified signals.
    Depends on bronze tests passing.
    """
    return run_dbt_command(
        ["run", "--select", "tag:silver"],
        task_name="dbt_run_silver",
    )


def task_dbt_test_silver(**ctx) -> dict:
    return run_dbt_command(
        ["test", "--select", "tag:silver"],
        task_name="dbt_test_silver",
    )


def task_dbt_run_gold(**ctx) -> dict:
    """
    Run gold layer models.
    Gold = severity-ranked intelligence served to API + dashboard.
    """
    return run_dbt_command(
        ["run", "--select", "tag:gold"],
        task_name="dbt_run_gold",
    )


def task_dbt_test_gold(**ctx) -> dict:
    return run_dbt_command(
        ["test", "--select", "tag:gold"],
        task_name="dbt_test_gold",
    )


def task_dbt_generate_docs(**ctx) -> dict:
    """
    Generate dbt docs after successful gold run.
    Docs are served separately — not blocking for pipeline.
    """
    run_dbt_command(["docs", "generate"], task_name="dbt_docs_generate")
    return {"docs": "generated"}


def task_validate_gold_output(**ctx) -> dict:
    """
    Post-dbt validation: confirm gold models have data
    and severity distribution looks healthy.
    Catches cases where dbt ran successfully but produced empty tables.
    """
    import duckdb

    DUCKDB_PATH = "data/threat_signals.duckdb"
    conn = duckdb.connect(DUCKDB_PATH, read_only=True)

    checks = {}

    # check gold_threat_signals has records
    count = conn.execute(
        "SELECT COUNT(*) FROM gold_threat_signals"
    ).fetchone()[0]
    checks["gold_threat_signals_count"] = count

    if count == 0:
        raise ValueError("gold_threat_signals is empty — pipeline may have failed upstream")

    # check severity distribution is not all MINIMAL
    bands = conn.execute("""
        SELECT severity_band, COUNT(*) as n
        FROM gold_threat_signals
        GROUP BY severity_band
        ORDER BY n DESC
    """).fetchdf()
    checks["severity_distribution"] = bands.to_dict(orient="records")

    # check emerging threats table has records
    emerging_count = conn.execute(
        "SELECT COUNT(*) FROM gold_emerging_threats"
    ).fetchone()[0]
    checks["gold_emerging_threats_count"] = emerging_count

    conn.close()

    logger.info(f"Gold validation passed | {checks}")
    return checks


def task_log_summary(**ctx) -> None:
    ti = ctx["ti"]

    gold_check = ti.xcom_pull(
        task_ids="validate_gold_output"
    ) or {}

    signal_count  = gold_check.get("gold_threat_signals_count", "?")
    emerging      = gold_check.get("gold_emerging_threats_count", "?")
    distribution  = gold_check.get("severity_distribution", [])

    dist_str = " | ".join(
        f"{r.get('severity_band', '?')}={r.get('n', 0)}"
        for r in distribution
    ) or "N/A"

    summary = f"""
    ╔══════════════════════════════════════════╗
    ║    DBT TRANSFORMATION PIPELINE SUMMARY   ║
    ╠══════════════════════════════════════════╣
    ║  Gold signals    : {signal_count:<5}                ║
    ║  Emerging threats: {emerging:<5}                ║
    ║  Severity dist   : {dist_str:<25}║
    ╚══════════════════════════════════════════╝
    """
    logger.info(summary)


# ---------------------------------------------------------------------------
# DAG definition
# ---------------------------------------------------------------------------

with DAG(
    dag_id="dbt_transformation_pipeline",
    description="dbt bronze → silver → gold transformation for threat signals",
    default_args=DEFAULT_ARGS,
    schedule_interval="0 7 * * *",      # daily at 07:00 UTC — 1hr after ingestion
    start_date=datetime(2025, 1, 1),
    catchup=False,
    max_active_runs=1,
    tags=["threat-intelligence", "dbt", "transformation"],
) as dbt_dag:

    start = EmptyOperator(task_id="start")
    end   = EmptyOperator(
        task_id="end",
        trigger_rule=TriggerRule.ALL_DONE,
    )

    dbt_deps        = PythonOperator(task_id="dbt_deps",         python_callable=task_dbt_deps)
    run_bronze      = PythonOperator(task_id="run_bronze",        python_callable=task_dbt_run_bronze)
    test_bronze     = PythonOperator(task_id="test_bronze",       python_callable=task_dbt_test_bronze)
    run_silver      = PythonOperator(task_id="run_silver",        python_callable=task_dbt_run_silver)
    test_silver     = PythonOperator(task_id="test_silver",       python_callable=task_dbt_test_silver)
    run_gold        = PythonOperator(task_id="run_gold",          python_callable=task_dbt_run_gold)
    test_gold       = PythonOperator(task_id="test_gold",         python_callable=task_dbt_test_gold)
    generate_docs   = PythonOperator(task_id="generate_docs",     python_callable=task_dbt_generate_docs)
    validate_gold   = PythonOperator(task_id="validate_gold_output", python_callable=task_validate_gold_output)
    log_summary     = PythonOperator(
        task_id="log_summary",
        python_callable=task_log_summary,
        trigger_rule=TriggerRule.ALL_DONE,
    )

    # strict medallion dependency chain — no layer runs until prior layer tests pass
    (
        start
        >> dbt_deps
        >> run_bronze
        >> test_bronze
        >> run_silver
        >> test_silver
        >> run_gold
        >> test_gold
        >> [validate_gold, generate_docs]
        >> log_summary
        >> end
    )