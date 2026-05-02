#!/usr/bin/env bash
#
# ==============================================================================
# DESPLIEGUE: Pipeline de logs de seguridad → Pub/Sub → Cloud Run parser → BQ
# ==============================================================================
#
# Este script crea TODA la infraestructura necesaria en GCP:
#   - APIs habilitadas
#   - Service Accounts con permisos mínimos (principio de menor privilegio)
#   - Dataset + tabla en BigQuery (particionada por día, clusterizada por vendor)
#   - Topic Pub/Sub para logs crudos + topic de dead-letter
#   - Cloud Run desplegado desde el código local
#   - Suscripción push de Pub/Sub → Cloud Run con autenticación
#
# IDEMPOTENTE: lo puedes correr varias veces. Si un recurso ya existe, lo detecta
# y continúa sin error.
#
# REQUISITOS PREVIOS:
#   - gcloud CLI instalado y autenticado:  gcloud auth login
#   - Tener un proyecto GCP con billing habilitado
#   - Permisos en el proyecto: Owner, o como mínimo:
#       roles/serviceusage.serviceUsageAdmin
#       roles/iam.serviceAccountAdmin
#       roles/run.admin
#       roles/pubsub.admin
#       roles/bigquery.admin
#
# USO:
#   ./deploy.sh
#   o sobreescribir variables:  PROJECT_ID=mi-proyecto REGION=us-east1 ./deploy.sh
# ==============================================================================

# `set -euo pipefail` es la guardia esencial de cualquier script bash serio:
#   -e: aborta si cualquier comando falla
#   -u: aborta si usas una variable no definida (atrapa typos en nombres de var)
#   -o pipefail: si algo en una pipe (|) falla, todo el pipeline falla
set -euo pipefail

# ------------------------------------------------------------------------------
# VARIABLES — ajusta estos valores a tu entorno
# ------------------------------------------------------------------------------
# Usa "${VAR:-default}" para permitir override desde el ambiente sin tocar el script.
PROJECT_ID="${PROJECT_ID:-mi-proyecto-poc}"
REGION="${REGION:-us-central1}"

# Nombres de recursos. Mantenlos en kebab-case (estándar de GCP).
SERVICE_NAME="${SERVICE_NAME:-log-parser}"
SA_NAME="${SA_NAME:-log-parser-sa}"          # Service Account que corre Cloud Run
INVOKER_SA_NAME="${INVOKER_SA_NAME:-pubsub-invoker-sa}"  # SA que Pub/Sub usa para invocar
TOPIC_NAME="${TOPIC_NAME:-raw-logs}"
DLQ_TOPIC_NAME="${DLQ_TOPIC_NAME:-raw-logs-dlq}"  # dead-letter queue
SUB_NAME="${SUB_NAME:-raw-logs-to-parser}"
BQ_DATASET="${BQ_DATASET:-network_logs}"
BQ_TABLE="${BQ_TABLE:-parsed_logs}"
BQ_LOCATION="${BQ_LOCATION:-US}"             # multi-region; usa "EU" si lo necesitas

# Derivados (no editar)
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
INVOKER_SA_EMAIL="${INVOKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Colores para el output (puro azúcar visual, opcional)
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}▶ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }

# ------------------------------------------------------------------------------
# 0. VALIDACIONES PREVIAS
# ------------------------------------------------------------------------------
log "Validando entorno..."

# Verificar que gcloud está instalado
command -v gcloud >/dev/null || { echo "ERROR: gcloud no instalado"; exit 1; }

# Verificar que estás autenticado
gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q . || {
    echo "ERROR: No hay cuenta autenticada. Corre: gcloud auth login"
    exit 1
}

# Setear el proyecto activo (sin esto, los comandos sin --project fallan)
gcloud config set project "$PROJECT_ID" --quiet

# Verificar que la carpeta del parser existe (esperamos correr este script desde
# el directorio padre del proyecto)
if [[ ! -f "main.py" || ! -f "Dockerfile" ]]; then
    echo "ERROR: Este script debe correrse desde el directorio del parser"
    echo "       (donde están main.py, Dockerfile, requirements.txt)"
    exit 1
fi

# ------------------------------------------------------------------------------
# 1. HABILITAR APIs
# ------------------------------------------------------------------------------
# Habilitar varias APIs en un solo comando es más rápido que una por una.
# Si ya están habilitadas, gcloud no se queja.
log "Habilitando APIs requeridas..."
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    pubsub.googleapis.com \
    bigquery.googleapis.com \
    bigquerystorage.googleapis.com \
    iam.googleapis.com \
    artifactregistry.googleapis.com \
    --quiet

# ------------------------------------------------------------------------------
# 2. SERVICE ACCOUNTS
# ------------------------------------------------------------------------------
# Buena práctica: NUNCA usar la default compute SA. Crea SAs dedicadas con
# permisos mínimos (least privilege).
#
# Necesitamos DOS service accounts:
#   a) log-parser-sa: la identidad con la que corre el Cloud Run.
#      Necesita permiso para INSERTAR en BigQuery.
#   b) pubsub-invoker-sa: la identidad que Pub/Sub usa para llamar al Cloud Run.
#      Necesita permiso para INVOCAR el Cloud Run (run.invoker).
# ------------------------------------------------------------------------------

log "Creando Service Account para Cloud Run: $SA_NAME"
# `|| true` hace el comando idempotente: si la SA ya existe, no rompe el script
gcloud iam service-accounts create "$SA_NAME" \
    --display-name="Log Parser Service Account" \
    --description="Corre el Cloud Run que parsea logs y escribe a BQ" \
    --quiet 2>/dev/null || warn "Service account $SA_NAME ya existe, continuando"

log "Creando Service Account para Pub/Sub invoker: $INVOKER_SA_NAME"
gcloud iam service-accounts create "$INVOKER_SA_NAME" \
    --display-name="Pub/Sub Invoker SA" \
    --description="Pub/Sub usa esta identidad para llamar al Cloud Run" \
    --quiet 2>/dev/null || warn "Service account $INVOKER_SA_NAME ya existe"

# ------------------------------------------------------------------------------
# 3. BIGQUERY: dataset + tabla particionada
# ------------------------------------------------------------------------------
# Particionar por día reduce costos: queries con WHERE event_timestamp >= ...
# leen solo los días relevantes. Clusterizar por vendor + source_ip acelera
# filtros típicos (ver actividad de un FortiGate, o de una IP específica).
# ------------------------------------------------------------------------------

log "Creando dataset BigQuery: $BQ_DATASET"
bq --location="$BQ_LOCATION" mk \
    --dataset \
    --description="Logs parseados de dispositivos de red/seguridad" \
    "${PROJECT_ID}:${BQ_DATASET}" 2>/dev/null || warn "Dataset ya existe"

# La tabla la creamos con un schema explícito (mejor que dejar que se autodetecte
# y descubrir 3 meses después que un campo es STRING cuando debía ser INT).
log "Creando tabla BigQuery: $BQ_TABLE"
bq mk \
    --table \
    --time_partitioning_field=ingest_timestamp \
    --time_partitioning_type=DAY \
    --clustering_fields=vendor,source_ip \
    --description="Logs parseados de firewalls/WAF/IPS" \
    "${PROJECT_ID}:${BQ_DATASET}.${BQ_TABLE}" \
    'ingest_timestamp:TIMESTAMP,vendor:STRING,product:STRING,raw_log:STRING,event_timestamp:TIMESTAMP,source_ip:STRING,source_port:INTEGER,dest_ip:STRING,dest_port:INTEGER,protocol:STRING,action:STRING,rule_name:STRING,user:STRING,bytes_sent:INTEGER,bytes_received:INTEGER,hostname:STRING,severity:STRING,message:STRING,extra:JSON' \
    2>/dev/null || warn "Tabla ya existe"

# Dar permisos a la SA del parser para escribir en la tabla
log "Otorgando permiso BigQuery Data Editor a $SA_NAME"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/bigquery.dataEditor" \
    --condition=None \
    --quiet >/dev/null

# Necesita también jobUser para poder hacer streaming inserts
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/bigquery.jobUser" \
    --condition=None \
    --quiet >/dev/null

# ------------------------------------------------------------------------------
# 4. PUB/SUB: topic principal + dead-letter queue
# ------------------------------------------------------------------------------
# El DLQ es el "buzón de mensajes problemáticos". Si un log falla N veces seguidas
# (típicamente por un bug en el parser), Pub/Sub lo manda al DLQ en vez de
# reintentar infinitamente. Sin esto, un solo log envenenado puede atascar todo.
# ------------------------------------------------------------------------------

log "Creando topic Pub/Sub: $TOPIC_NAME"
gcloud pubsub topics create "$TOPIC_NAME" \
    --quiet 2>/dev/null || warn "Topic $TOPIC_NAME ya existe"

log "Creando topic dead-letter queue: $DLQ_TOPIC_NAME"
gcloud pubsub topics create "$DLQ_TOPIC_NAME" \
    --quiet 2>/dev/null || warn "Topic DLQ ya existe"

# ------------------------------------------------------------------------------
# 5. DESPLEGAR CLOUD RUN
# ------------------------------------------------------------------------------
# `--source .` le dice a Cloud Run: "construye la imagen desde este directorio"
# usando Cloud Build + el Dockerfile que tengamos.
#
# Flags importantes:
#   --no-allow-unauthenticated: NUNCA expongas un endpoint público sin razón.
#                               Pub/Sub se autenticará con OIDC.
#   --service-account: ejecutar con la SA dedicada (no la default).
#   --concurrency=80: cuántos requests simultáneos por instancia. 80 es el default
#                     de Cloud Run, está bien para IO-bound.
#   --max-instances: tope de escalado. Pónlo según tu volumen esperado.
#                    En PoC, 10 es razonable. En prod, súbelo a 100+.
#   --min-instances=0: escala a cero (cero costo cuando no hay tráfico).
# ------------------------------------------------------------------------------

log "Desplegando Cloud Run: $SERVICE_NAME (esto tarda 2-5 min)..."
gcloud run deploy "$SERVICE_NAME" \
    --source . \
    --region "$REGION" \
    --service-account "$SA_EMAIL" \
    --no-allow-unauthenticated \
    --memory 512Mi \
    --cpu 1 \
    --concurrency 80 \
    --min-instances 0 \
    --max-instances 10 \
    --timeout 60 \
    --set-env-vars "GCP_PROJECT=${PROJECT_ID},BQ_DATASET=${BQ_DATASET},BQ_TABLE=${BQ_TABLE}" \
    --quiet

# Capturar la URL del servicio recién desplegado para usarla en la suscripción
PARSER_URL=$(gcloud run services describe "$SERVICE_NAME" \
    --region "$REGION" \
    --format='value(status.url)')
log "Cloud Run desplegado en: $PARSER_URL"

# ------------------------------------------------------------------------------
# 6. PERMISOS PARA QUE PUB/SUB INVOQUE EL CLOUD RUN
# ------------------------------------------------------------------------------
# La SA invoker necesita el rol run.invoker en este servicio específico
# (no a nivel proyecto, mejor scope reducido).
# ------------------------------------------------------------------------------

log "Permitiendo a $INVOKER_SA_NAME invocar el Cloud Run"
gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
    --region "$REGION" \
    --member="serviceAccount:${INVOKER_SA_EMAIL}" \
    --role="roles/run.invoker" \
    --quiet >/dev/null

# El service agent de Pub/Sub también necesita poder generar tokens OIDC
# en nombre de la SA invoker. Esto es un detalle sutil pero crítico.
PUBSUB_SERVICE_AGENT="service-$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')@gcp-sa-pubsub.iam.gserviceaccount.com"
log "Permitiendo al Pub/Sub Service Agent crear tokens OIDC"
gcloud iam service-accounts add-iam-policy-binding "$INVOKER_SA_EMAIL" \
    --member="serviceAccount:${PUBSUB_SERVICE_AGENT}" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --quiet >/dev/null

# ------------------------------------------------------------------------------
# 7. CREAR SUSCRIPCIÓN PUSH
# ------------------------------------------------------------------------------
# Esta es la pieza que conecta todo: cuando llegue un mensaje al topic,
# Pub/Sub hará un POST autenticado al Cloud Run.
#
# Detalles importantes:
#   --ack-deadline: cuánto tiempo le damos al Cloud Run para procesar antes de
#                   considerar timeout. 60s es suficiente para un parser ligero.
#   --max-delivery-attempts=5: tras 5 fallos, el mensaje va al DLQ.
#   --message-retention-duration: si DLQ se llena, cuánto retener. 7 días default.
# ------------------------------------------------------------------------------

log "Creando suscripción push: $SUB_NAME"
gcloud pubsub subscriptions create "$SUB_NAME" \
    --topic "$TOPIC_NAME" \
    --push-endpoint "$PARSER_URL" \
    --push-auth-service-account "$INVOKER_SA_EMAIL" \
    --ack-deadline 60 \
    --message-retention-duration 7d \
    --dead-letter-topic "$DLQ_TOPIC_NAME" \
    --max-delivery-attempts 5 \
    --quiet 2>/dev/null || warn "Suscripción $SUB_NAME ya existe (no se actualiza, bórrala manualmente si quieres recrear)"

# Para que el DLQ funcione, el service agent de Pub/Sub necesita poder publicar
# en el topic DLQ y consumir del topic principal.
log "Configurando permisos para DLQ"
gcloud pubsub topics add-iam-policy-binding "$DLQ_TOPIC_NAME" \
    --member="serviceAccount:${PUBSUB_SERVICE_AGENT}" \
    --role="roles/pubsub.publisher" \
    --quiet >/dev/null

gcloud pubsub subscriptions add-iam-policy-binding "$SUB_NAME" \
    --member="serviceAccount:${PUBSUB_SERVICE_AGENT}" \
    --role="roles/pubsub.subscriber" \
    --quiet >/dev/null

# ------------------------------------------------------------------------------
# 8. RESUMEN FINAL
# ------------------------------------------------------------------------------
cat <<EOF

${GREEN}═══════════════════════════════════════════════════════════════════════════
  ✓ DESPLIEGUE COMPLETADO
═══════════════════════════════════════════════════════════════════════════${NC}

Recursos creados:
  • Proyecto:           $PROJECT_ID
  • Region:             $REGION
  • Cloud Run:          $PARSER_URL
  • Pub/Sub topic:      projects/$PROJECT_ID/topics/$TOPIC_NAME
  • DLQ topic:          projects/$PROJECT_ID/topics/$DLQ_TOPIC_NAME
  • Subscription:       projects/$PROJECT_ID/subscriptions/$SUB_NAME
  • BigQuery tabla:     $PROJECT_ID:$BQ_DATASET.$BQ_TABLE

──────────────────────────────────────────────────────────────────────────
  PROBAR EL PIPELINE
──────────────────────────────────────────────────────────────────────────

# Publicar un log de prueba (Fortinet)
gcloud pubsub topics publish $TOPIC_NAME --message='date=2026-04-01 time=14:22:10 devname="FGT" devid="FG100E0AB12345678" srcip=192.168.10.25 srcport=52311 dstip=203.0.113.10 dstport=443 action="blocked"'

# Esperar 5-10 segundos y consultar BigQuery
bq query --use_legacy_sql=false "
SELECT vendor, source_ip, dest_ip, action
FROM \\\`$PROJECT_ID.$BQ_DATASET.$BQ_TABLE\\\`
WHERE DATE(ingest_timestamp) = CURRENT_DATE()
ORDER BY ingest_timestamp DESC
LIMIT 10"

──────────────────────────────────────────────────────────────────────────
  VER LOGS DEL PARSER
──────────────────────────────────────────────────────────────────────────

gcloud run logs read $SERVICE_NAME --region $REGION --limit 50

──────────────────────────────────────────────────────────────────────────
  MENSAJES FALLIDOS (DLQ)
──────────────────────────────────────────────────────────────────────────

# Crear suscripción al DLQ (solo la primera vez) para inspeccionar mensajes muertos
gcloud pubsub subscriptions create ${DLQ_TOPIC_NAME}-inspector --topic $DLQ_TOPIC_NAME

# Leer mensajes del DLQ
gcloud pubsub subscriptions pull ${DLQ_TOPIC_NAME}-inspector --auto-ack --limit 10

──────────────────────────────────────────────────────────────────────────
  LIMPIAR TODO (cuidado, es destructivo)
──────────────────────────────────────────────────────────────────────────

./teardown.sh    # script separado, no incluido aquí

EOF
