"""
Cliente BigQuery minimalista.

Schema de la tabla raw_logs (2 columnas):
  - ingest_timestamp: TIMESTAMP (campo de partición)
  - raw_log: STRING (el syslog crudo, sin tocar)

Para producción a alto volumen, considera migrar a Storage Write API
(google.cloud.bigquery_storage_v1) que es ~50% más barato que streaming inserts.
"""
import os
import logging
from google.cloud import bigquery
from google.api_core import retry

logger = logging.getLogger(__name__)

PROJECT_ID = os.environ.get("GCP_PROJECT", "")
DATASET = os.environ.get("BQ_DATASET", "network_logs")
TABLE = os.environ.get("BQ_TABLE", "raw_logs")

_client = bigquery.Client() if PROJECT_ID else None


def get_table_ref() -> str:
    return f"{PROJECT_ID}.{DATASET}.{TABLE}"


@retry.Retry(predicate=retry.if_transient_error, initial=1.0, maximum=10.0, deadline=30.0)
def insert_row(row: dict) -> None:
    """Inserta una fila. Reintenta automáticamente en errores transitorios."""
    if _client is None:
        raise RuntimeError("BigQuery client no inicializado. ¿Falta GCP_PROJECT?")

    errors = _client.insert_rows_json(get_table_ref(), [row])
    if errors:
        logger.error("Error insertando fila: %s", errors)
        raise RuntimeError(f"BQ insert errors: {errors}")
