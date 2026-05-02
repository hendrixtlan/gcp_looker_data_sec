#!/usr/bin/env bash
# Borra todos los recursos creados por deploy.sh

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-mi-proyecto-poc}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-log-ingestor}"
SA_NAME="${SA_NAME:-log-ingestor-sa}"
INVOKER_SA_NAME="${INVOKER_SA_NAME:-pubsub-invoker-sa}"
TOPIC_NAME="${TOPIC_NAME:-raw-logs}"
DLQ_TOPIC_NAME="${DLQ_TOPIC_NAME:-raw-logs-dlq}"
SUB_NAME="${SUB_NAME:-raw-logs-to-ingestor}"
BQ_DATASET="${BQ_DATASET:-network_logs}"

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
INVOKER_SA_EMAIL="${INVOKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if [[ "${FORCE:-0}" != "1" ]]; then
    echo "⚠ Vas a BORRAR todos los recursos del proyecto $PROJECT_ID"
    read -rp "¿Continuar? (escribe 'si'): " CONFIRM
    [[ "$CONFIRM" == "si" ]] || { echo "Cancelado."; exit 0; }
fi

gcloud config set project "$PROJECT_ID" --quiet

echo "▶ Borrando suscripción..."
gcloud pubsub subscriptions delete "$SUB_NAME" --quiet 2>/dev/null || true

echo "▶ Borrando topics..."
gcloud pubsub topics delete "$TOPIC_NAME" --quiet 2>/dev/null || true
gcloud pubsub topics delete "$DLQ_TOPIC_NAME" --quiet 2>/dev/null || true

echo "▶ Borrando Cloud Run..."
gcloud run services delete "$SERVICE_NAME" --region "$REGION" --quiet 2>/dev/null || true

echo "▶ Borrando dataset BigQuery..."
bq rm -rf "${PROJECT_ID}:${BQ_DATASET}" 2>/dev/null || true

echo "▶ Borrando Service Accounts..."
gcloud iam service-accounts delete "$SA_EMAIL" --quiet 2>/dev/null || true
gcloud iam service-accounts delete "$INVOKER_SA_EMAIL" --quiet 2>/dev/null || true

echo "✓ Limpieza completada."
