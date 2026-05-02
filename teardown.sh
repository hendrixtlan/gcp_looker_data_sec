#!/usr/bin/env bash
#
# ==============================================================================
# TEARDOWN: Borra TODOS los recursos creados por deploy.sh
# ==============================================================================
#
# CUIDADO: Esto es destructivo. Borra:
#   - El servicio Cloud Run
#   - Los topics y suscripciones de Pub/Sub
#   - La tabla y dataset de BigQuery (con todos los logs)
#   - Las service accounts
#
# Las APIs habilitadas NO se deshabilitan (no cuesta dinero tenerlas habilitadas
# y deshabilitar puede afectar otros servicios del proyecto).
#
# USO:
#   ./teardown.sh                  # pide confirmación
#   FORCE=1 ./teardown.sh          # sin confirmación (úsalo en CI)
# ==============================================================================

set -euo pipefail

# Mismas variables que deploy.sh — debe coincidir
PROJECT_ID="${PROJECT_ID:-mi-proyecto-poc}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-log-parser}"
SA_NAME="${SA_NAME:-log-parser-sa}"
INVOKER_SA_NAME="${INVOKER_SA_NAME:-pubsub-invoker-sa}"
TOPIC_NAME="${TOPIC_NAME:-raw-logs}"
DLQ_TOPIC_NAME="${DLQ_TOPIC_NAME:-raw-logs-dlq}"
SUB_NAME="${SUB_NAME:-raw-logs-to-parser}"
BQ_DATASET="${BQ_DATASET:-network_logs}"

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
INVOKER_SA_EMAIL="${INVOKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Confirmación interactiva (skipeable con FORCE=1)
if [[ "${FORCE:-0}" != "1" ]]; then
    echo "⚠ Vas a BORRAR todos los recursos del proyecto $PROJECT_ID"
    echo "  Esto incluye la tabla BigQuery con TODOS los logs almacenados."
    read -rp "¿Continuar? (escribe 'si' para confirmar): " CONFIRM
    [[ "$CONFIRM" == "si" ]] || { echo "Cancelado."; exit 0; }
fi

gcloud config set project "$PROJECT_ID" --quiet

# Las eliminaciones se hacen en orden inverso al de creación, y cada una
# usa `|| true` para que si el recurso ya no existe, no rompa el script.

echo "▶ Borrando suscripción Pub/Sub..."
gcloud pubsub subscriptions delete "$SUB_NAME" --quiet 2>/dev/null || true
gcloud pubsub subscriptions delete "${DLQ_TOPIC_NAME}-inspector" --quiet 2>/dev/null || true

echo "▶ Borrando topics Pub/Sub..."
gcloud pubsub topics delete "$TOPIC_NAME" --quiet 2>/dev/null || true
gcloud pubsub topics delete "$DLQ_TOPIC_NAME" --quiet 2>/dev/null || true

echo "▶ Borrando Cloud Run..."
gcloud run services delete "$SERVICE_NAME" --region "$REGION" --quiet 2>/dev/null || true

echo "▶ Borrando dataset BigQuery (con todas sus tablas)..."
# -f: force, -r: recursive (borra tablas dentro del dataset)
bq rm -rf "${PROJECT_ID}:${BQ_DATASET}" 2>/dev/null || true

echo "▶ Borrando Service Accounts..."
gcloud iam service-accounts delete "$SA_EMAIL" --quiet 2>/dev/null || true
gcloud iam service-accounts delete "$INVOKER_SA_EMAIL" --quiet 2>/dev/null || true

echo "✓ Limpieza completada."
echo "  Las APIs habilitadas NO se deshabilitaron (no cuesta tenerlas activas)."
