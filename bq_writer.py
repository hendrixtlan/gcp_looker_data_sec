"""
Cliente para escribir filas a BigQuery.

Usamos `insert_rows_json` (streaming inserts clásicos) por simplicidad en el PoC.
Para producción a alto volumen, migrar a Storage Write API
(google.cloud.bigquery_storage_v1) que es ~50% más barato.
"""
import os
import logging
from typing import Iterable
from google.cloud import bigquery
from google.api_core import retry

logger = logging.getLogger(__name__)

PROJECT_ID = os.environ.get("GCP_PROJECT", "")
DATASET = os.environ.get("BQ_DATASET", "network_logs")
TABLE = os.environ.get("BQ_TABLE", "parsed_logs")

# Cliente global, reusa conexiones HTTP entre invocaciones
_client = bigquery.Client() if PROJECT_ID else None


def get_table_ref() -> str:
    return f"{PROJECT_ID}.{DATASET}.{TABLE}"


@retry.Retry(predicate=retry.if_transient_error, initial=1.0, maximum=10.0, deadline=30.0)
def insert_rows(rows: Iterable[dict]) -> None:
    """
    Inserta filas en BigQuery. Reintenta automáticamente en errores transitorios.
    Si una fila individual tiene error de schema, la registramos pero NO reintentamos
    todo el batch (o quedaríamos en loop infinito).
    """
    if _client is None:
        raise RuntimeError("BigQuery client no inicializado. ¿Falta GCP_PROJECT?")

    rows = list(rows)
    if not rows:
        return

    errors = _client.insert_rows_json(get_table_ref(), rows)
    if errors:
        # Errores de schema: log + descarta la fila problemática (no reintenta)
        for error in errors:
            logger.error(
                "Error insertando fila índice %s: %s",
                error.get("index"), error.get("errors")
            )
        # Si TODAS fallaron, levantamos para que Pub/Sub reintente
        if len(errors) == len(rows):
            raise RuntimeError(f"Todas las filas fallaron: {errors[:3]}")
