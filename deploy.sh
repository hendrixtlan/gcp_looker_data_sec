#!/usr/bin/env bash
#
# ==============================================================================
# DESPLIEGUE: Pipeline raw — Pub/Sub → Cloud Run passthrough → BQ raw_logs
# ==============================================================================
#
# Diferencia respecto a una versión "parser-en-pipeline":
#   - Cloud Run NO parsea: solo decodifica y mete el log a BQ tal cual
#   - Tabla BQ tiene SOLO 2 columnas: ingest_timestamp + raw_log
#   - Todo el parseo vive en LookML (regex sobre raw_log)
#
# Ventaja: analistas iteran regex sin redeploys de pipelines
# Costo: queries más caras en BQ (mitigado con derived table materializada)
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# VARIABLES — ajusta a tu entorno
# ------------------------------------------------------------------------------
PROJECT_ID="${PROJECT_ID:-mi-proyecto-poc}"
REGION="${REGION:-us-central1}"

SERVICE_NAME="${SERVICE_NAME:-log-ingestor}"
SA_NAME="${SA_NAME:-log-ingestor-sa}"
INVOKER_SA_NAME="${INVOKER_SA_NAME:-pubsub-invoker-sa}"
TOPIC_NAME="${TOPIC_NAME:-raw-logs}"
DLQ_TOPIC_NAME="${DLQ_TOPIC_NAME:-raw-logs-dlq}"
SUB_NAME="${SUB_NAME:-raw-logs-to-ingestor}"
BQ_DATASET="${BQ_DATASET:-network_logs}"
BQ_TABLE="${BQ_TABLE:-raw_logs}"
BQ_LOCATION="${BQ_LOCATION:-US}"

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
INVOKER_SA_EMAIL="${INVOKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}▶ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }

# ------------------------------------------------------------------------------
# 0. VALIDACIONES
# ------------------------------------------------------------------------------
log "Validando entorno..."
command -v gcloud >/dev/null || { echo "ERROR: gcloud no instalado"; exit 1; }
gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q . || {
    echo "ERROR: No hay cuenta autenticada. Corre: gcloud auth login"
    exit 1
}
gcloud config set project "$PROJECT_ID" --quiet

[[ -f "main.py" && -f "Dockerfile" ]] || {
    echo "ERROR: Corre este script desde el directorio del proyecto"; exit 1;
}

# ------------------------------------------------------------------------------
# 1. APIs
# ------------------------------------------------------------------------------
log "Habilitando APIs..."
gcloud services enable \
    run.googleapis.com cloudbuild.googleapis.com pubsub.googleapis.com \
    bigquery.googleapis.com bigquerystorage.googleapis.com \
    iam.googleapis.com artifactregistry.googleapis.com \
    --quiet

# ------------------------------------------------------------------------------
# 2. SERVICE ACCOUNTS
# ------------------------------------------------------------------------------
log "Creando Service Account: $SA_NAME"
gcloud iam service-accounts create "$SA_NAME" \
    --display-name="Log Ingestor SA" \
    --description="Cloud Run que decodifica syslog y mete a BQ" \
    --quiet 2>/dev/null || warn "$SA_NAME ya existe"

log "Creando Service Account: $INVOKER_SA_NAME"
gcloud iam service-accounts create "$INVOKER_SA_NAME" \
    --display-name="Pub/Sub Invoker SA" \
    --quiet 2>/dev/null || warn "$INVOKER_SA_NAME ya existe"

# ------------------------------------------------------------------------------
# 3. BIGQUERY: dataset + tabla MÍNIMA
# ------------------------------------------------------------------------------
# La tabla tiene SOLO 2 columnas. Todo el parseo se hace en LookML.
# Particionada por ingest_timestamp para que las queries con WHERE
# ingest_timestamp >= ... lean solo las particiones necesarias.
# ------------------------------------------------------------------------------

log "Creando dataset BigQuery: $BQ_DATASET"
bq --location="$BQ_LOCATION" mk \
    --dataset \
    --description="Logs crudos de dispositivos de red/seguridad" \
    "${PROJECT_ID}:${BQ_DATASET}" 2>/dev/null || warn "Dataset ya existe"

log "Creando tabla BigQuery: $BQ_TABLE (schema mínimo)"
bq mk \
    --table \
    --time_partitioning_field=ingest_timestamp \
    --time_partitioning_type=DAY \
    --time_partitioning_expiration=7776000 \
    --description="Syslog crudo. Parseo se hace en LookML." \
    "${PROJECT_ID}:${BQ_DATASET}.${BQ_TABLE}" \
    'ingest_timestamp:TIMESTAMP,raw_log:STRING' \
    2>/dev/null || warn "Tabla ya existe"

# Nota sobre --time_partitioning_expiration=7776000: 90 días en segundos.
# Particiones más viejas se borran automáticamente. Ajusta según retention policy.
# Si necesitas más, súbelo o quítalo.

log "Permisos BQ para $SA_NAME"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/bigquery.dataEditor" \
    --condition=None --quiet >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/bigquery.jobUser" \
    --condition=None --quiet >/dev/null

# ------------------------------------------------------------------------------
# 4. PUB/SUB
# ------------------------------------------------------------------------------
log "Creando topic: $TOPIC_NAME"
gcloud pubsub topics create "$TOPIC_NAME" --quiet 2>/dev/null || warn "Topic ya existe"

log "Creando topic DLQ: $DLQ_TOPIC_NAME"
gcloud pubsub topics create "$DLQ_TOPIC_NAME" --quiet 2>/dev/null || warn "DLQ ya existe"

# ------------------------------------------------------------------------------
# 5. CLOUD RUN
# ------------------------------------------------------------------------------
log "Desplegando Cloud Run: $SERVICE_NAME (3-5 min)..."
gcloud run deploy "$SERVICE_NAME" \
    --source . \
    --region "$REGION" \
    --service-account "$SA_EMAIL" \
    --no-allow-unauthenticated \
    --memory 512Mi --cpu 1 \
    --concurrency 80 \
    --min-instances 0 --max-instances 10 \
    --timeout 60 \
    --set-env-vars "GCP_PROJECT=${PROJECT_ID},BQ_DATASET=${BQ_DATASET},BQ_TABLE=${BQ_TABLE}" \
    --quiet

INGESTOR_URL=$(gcloud run services describe "$SERVICE_NAME" \
    --region "$REGION" --format='value(status.url)')
log "Cloud Run desplegado en: $INGESTOR_URL"

# ------------------------------------------------------------------------------
# 6. PERMISOS PARA QUE PUB/SUB INVOQUE EL CLOUD RUN
# ------------------------------------------------------------------------------
log "Permitiendo a $INVOKER_SA_NAME invocar Cloud Run"
gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
    --region "$REGION" \
    --member="serviceAccount:${INVOKER_SA_EMAIL}" \
    --role="roles/run.invoker" \
    --quiet >/dev/null

PUBSUB_SERVICE_AGENT="service-$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')@gcp-sa-pubsub.iam.gserviceaccount.com"
log "Permisos OIDC para Pub/Sub Service Agent"
gcloud iam service-accounts add-iam-policy-binding "$INVOKER_SA_EMAIL" \
    --member="serviceAccount:${PUBSUB_SERVICE_AGENT}" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --quiet >/dev/null

# ------------------------------------------------------------------------------
# 7. SUSCRIPCIÓN PUSH
# ------------------------------------------------------------------------------
log "Creando suscripción push: $SUB_NAME"
gcloud pubsub subscriptions create "$SUB_NAME" \
    --topic "$TOPIC_NAME" \
    --push-endpoint "$INGESTOR_URL" \
    --push-auth-service-account "$INVOKER_SA_EMAIL" \
    --ack-deadline 60 \
    --message-retention-duration 7d \
    --dead-letter-topic "$DLQ_TOPIC_NAME" \
    --max-delivery-attempts 5 \
    --quiet 2>/dev/null || warn "Suscripción ya existe"

gcloud pubsub topics add-iam-policy-binding "$DLQ_TOPIC_NAME" \
    --member="serviceAccount:${PUBSUB_SERVICE_AGENT}" \
    --role="roles/pubsub.publisher" --quiet >/dev/null

gcloud pubsub subscriptions add-iam-policy-binding "$SUB_NAME" \
    --member="serviceAccount:${PUBSUB_SERVICE_AGENT}" \
    --role="roles/pubsub.subscriber" --quiet >/dev/null

# ------------------------------------------------------------------------------
# 8. RESUMEN
# ------------------------------------------------------------------------------
cat <<EOF

${GREEN}═══════════════════════════════════════════════════════════════════════════
  ✓ DESPLIEGUE COMPLETADO
═══════════════════════════════════════════════════════════════════════════${NC}

Recursos:
  • Cloud Run:       $INGESTOR_URL
  • Pub/Sub topic:   projects/$PROJECT_ID/topics/$TOPIC_NAME
  • DLQ:             projects/$PROJECT_ID/topics/$DLQ_TOPIC_NAME
  • Subscription:    projects/$PROJECT_ID/subscriptions/$SUB_NAME
  • Tabla BQ:        $PROJECT_ID:$BQ_DATASET.$BQ_TABLE (2 columnas)

──────────────────────────────────────────────────────────────────────────
  PROBAR
──────────────────────────────────────────────────────────────────────────

# Publicar un log de ejemplo
gcloud pubsub topics publish $TOPIC_NAME --message='date=2026-04-01 time=14:22:10 devname="FGT" srcip=192.168.10.25 dstip=203.0.113.10 action="blocked"'

# Verificar que entró a BQ
bq query --use_legacy_sql=false "
SELECT ingest_timestamp, raw_log
FROM \\\`$PROJECT_ID.$BQ_DATASET.$BQ_TABLE\\\`
WHERE DATE(ingest_timestamp) = CURRENT_DATE()
ORDER BY ingest_timestamp DESC LIMIT 5"

# Probar el regex de extracción de IP (lo mismo que hace LookML)
bq query --use_legacy_sql=false "
SELECT
  ingest_timestamp,
  COALESCE(
    REGEXP_EXTRACT(raw_log, r'(?:^|\\s)srcip=([0-9]{1,3}(?:\\.[0-9]{1,3}){3})'),
    REGEXP_EXTRACT(raw_log, r'(?:^|\\s)SRC=([0-9]{1,3}(?:\\.[0-9]{1,3}){3})'),
    REGEXP_EXTRACT(raw_log, r'\\|src=([0-9]{1,3}(?:\\.[0-9]{1,3}){3})\\|'),
    REGEXP_EXTRACT(raw_log, r'(?:^|\\s)src=([0-9]{1,3}(?:\\.[0-9]{1,3}){3})(?:\\s|\$)')
  ) AS source_ip
FROM \\\`$PROJECT_ID.$BQ_DATASET.$BQ_TABLE\\\`
WHERE DATE(ingest_timestamp) = CURRENT_DATE()
LIMIT 10"

──────────────────────────────────────────────────────────────────────────
  LOGS DEL CLOUD RUN
──────────────────────────────────────────────────────────────────────────

gcloud run logs read $SERVICE_NAME --region $REGION --limit 50

EOF
