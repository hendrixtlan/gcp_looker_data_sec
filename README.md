# Pipeline de logs de seguridad → BigQuery → LookML

Pipeline minimalista para ingestar logs syslog de dispositivos de red y
seguridad (Fortinet, Palo Alto, Cisco ASA, Check Point, WatchGuard, etc.) en
BigQuery, donde se almacenan **sin parsear**. Todo el parseo de campos (IPs,
puertos, acciones, vendor) se hace en **LookML** vía regex sobre la columna
`raw_log`.

## ¿Por qué este diseño?

**Flexibilidad sobre eficiencia.** Cuando aparece un vendor nuevo o cambia un
formato, los analistas ajustan los regex en LookML y hacen Deploy. No hay que
rebuilding de imágenes Docker, ni redeploys de Cloud Run, ni código que
reviewar y mergear. La latencia entre "vi un log raro" y "lo veo parseado en
mi dashboard" baja de horas a minutos.

El precio que pagas: queries en BigQuery cuestan más porque cada vez se
ejecutan los regex. Esto se mitiga con una **derived table materializada** en
LookML que precomputa los campos cada hora.

## Arquitectura

```
                    ┌──────────────────────────────┐
                    │    DISPOSITIVOS DE RED       │
                    │  Fortinet · Palo Alto · ASA  │
                    │  WatchGuard · CheckPoint     │
                    │  ModSecurity · iptables ...  │
                    └──────────────┬───────────────┘
                                   │ syslog UDP/TCP
                                   ▼
                    ┌──────────────────────────────┐
                    │      COLECTOR SYSLOG         │
                    │   (Fluent Bit / Vector)      │
                    │      [siguiente fase]        │
                    └──────────────┬───────────────┘
                                   │ publish
                                   ▼
                    ┌──────────────────────────────┐
                    │      PUB/SUB · raw-logs      │
                    │   (buffer + retry + DLQ)     │
                    └──────────────┬───────────────┘
                                   │ push (POST autenticado)
                                   ▼
                ┌──────────────────────────────────────┐
                │     CLOUD RUN · log-ingestor         │
                │  (passthrough: solo decode + insert) │
                └──────────────┬───────────────────────┘
                               │
                               ▼
                ┌──────────────────────────────┐
                │  BIGQUERY · raw_logs         │
                │  ┌────────────────────────┐  │
                │  │ ingest_timestamp  TS   │  │
                │  │ raw_log           STR  │  │
                │  └────────────────────────┘  │
                │  Particionada por día        │
                │  Retention: 90 días          │
                └──────────────┬───────────────┘
                               │
                               ▼
                ┌──────────────────────────────────────┐
                │     LOOKER · raw_logs.view.lkml      │
                │  ┌────────────────────────────────┐  │
                │  │  ─ source_ip   (regex COALESCE)│  │
                │  │  ─ dest_ip     (regex COALESCE)│  │
                │  │  ─ vendor      (CASE pattern)  │  │
                │  │  ─ action      (regex+normaliz)│  │
                │  │  ─ ports       (regex SAFE_CAST│  │
                │  └────────────────────────────────┘  │
                │                                      │
                │  ┌────────────────────────────────┐  │
                │  │  raw_logs_parsed (PDT)         │  │
                │  │  Materializa cada 1h           │  │
                │  └────────────────────────────────┘  │
                └──────────────┬───────────────────────┘
                               │
                               ▼
                        Dashboards
```

## Estructura del proyecto

```
parser/
├── README.md                ← este archivo
├── Dockerfile               ← imagen para Cloud Run
├── requirements.txt         ← solo flask + bigquery client
├── deploy.sh                ← despliegue idempotente
├── teardown.sh              ← limpieza
├── main.py                  ← passthrough Pub/Sub → BQ
├── bq_writer.py             ← cliente BigQuery
└── lookml/
    ├── manifest.lkml        ← constantes de proyecto
    ├── network_security.model.lkml ← model + datagroup
    └── raw_logs.view.lkml   ← view con todos los regex
```

## Schema BigQuery

Tabla `network_logs.raw_logs`:

| Columna | Tipo | Descripción |
|---|---|---|
| `ingest_timestamp` | TIMESTAMP | Cuándo entró a BQ (campo de partición) |
| `raw_log` | STRING | Syslog crudo, sin tocar |

Eso es todo. Particionada diariamente, con retention de 90 días (configurable
en `deploy.sh`).

## Vendors soportados en LookML

| Vendor | Patrón de detección | Regex IP origen |
|--------|---------------------|------------------|
| Fortinet FortiGate | `devname="FG..."` | `srcip=` |
| Palo Alto LEEF | `LEEF: ... Palo Alto` | `\|src=...\|` |
| WatchGuard LEEF | `LEEF: ... WatchGuard` | `\|src=...\|` |
| Check Point CEF | `CEF: ... Check Point` | `src=` |
| Cisco ASA/FTD | `%ASA-X-XXXXXX` | `from X:IP/port` |
| Juniper SRX | `RT_FLOW` o `source-address=` | `source-address=` |
| SonicWall | `id=firewall sn=` | `src=IP:` |
| iptables/Netfilter | `SRC=...DST=...PROTO=` | `SRC=` (mayús) |
| ModSecurity | `modsec` o `OWASP_CRS` | `client:` |
| CEF/LEEF genérico | `CEF:` o `LEEF:` | varios |

Logs no reconocidos quedan como `vendor = 'unknown'` en la dimension. Hay un
measure `unknown_vendor_count` para detectar qué tan bien está cubriendo el
parser y priorizar agregar nuevos patrones.

## Despliegue

```bash
# 1. Edita variables en deploy.sh (PROJECT_ID, REGION)
vim deploy.sh

# 2. Despliega (3-5 min)
./deploy.sh

# 3. Probar con un log
gcloud pubsub topics publish raw-logs --message='date=2026-04-01 time=14:22:10 devname="FGT" srcip=192.168.10.25 dstip=203.0.113.10 action="blocked"'

# 4. Verificar en BQ
bq query --use_legacy_sql=false "SELECT * FROM PROJECT.network_logs.raw_logs LIMIT 5"
```

## Configurar LookML

1. **En Looker**: Admin → Connections → New Connection
   - Type: BigQuery Standard SQL
   - Project: tu proyecto GCP
   - Dataset: `network_logs`
   - Service account: con `roles/bigquery.dataViewer` mínimo
   - Nombre: `gcp_logs` (o cambia `connection:` en el model)

2. **Crear proyecto LookML** y subir los 3 archivos de la carpeta `lookml/`:
   - `manifest.lkml` → raíz
   - `network_security.model.lkml` → raíz
   - `raw_logs.view.lkml` → carpeta `views/`

3. **Editar `manifest.lkml`** con tu PROJECT_ID y dataset.

4. **Validate LookML** (botón en la UI) y **Deploy to Production**.

## Cómo agregar un vendor nuevo

Sin redeploy, sin pipeline, sin código Python. Solo editar `raw_logs.view.lkml`:

```lookml
dimension: source_ip {
  sql: COALESCE(
    -- ... patrones existentes ...

    -- NUEVO: Sophos XG: src_ip="1.2.3.4"
    REGEXP_EXTRACT(${TABLE}.raw_log,
      r'src_ip="?([0-9]{1,3}(?:\.[0-9]{1,3}){3})"?')
  ) ;;
}
```

Y en la dimension `vendor`:

```lookml
WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'device_name="SFW"') THEN 'sophos'
```

Validar y deploy. Listo. Los datos ya en BQ inmediatamente reflejan el nuevo
parser (regex ejecuta en query time).

## Performance y costos

**Sin derived table** (regex en cada query):
- 1 GB de raw_logs escaneado ≈ $0.005
- Una query típica de dashboard sobre 30 días puede escanear 50-100 GB
- ≈ $0.50/query × 100 dashboards/día × 30 días = ~$1500/mes en BQ

**Con derived table materializada** (recomendado):
- Refresh por hora: 1 scan completo a `raw_logs` + escritura a tabla parseada
- Dashboards consultan la tabla parseada (clusterizada, barata)
- ≈ $50-200/mes para volumen medio

**Mitigaciones adicionales**:
- `always_filter` en el explore fuerza filtros temporales
- Particionado diario en `raw_logs` evita escanear datos viejos
- Si volumen es alto, considera limitar el COALESCE a los regex relevantes
  por particionado de tabla (ej: tabla por vendor)

## Operación

```bash
# Logs del Cloud Run
gcloud run logs read log-ingestor --region us-central1 --limit 50

# Mensajes en DLQ (los que fallaron 5 veces)
gcloud pubsub subscriptions create raw-logs-dlq-inspector --topic raw-logs-dlq
gcloud pubsub subscriptions pull raw-logs-dlq-inspector --auto-ack --limit 10

# Detectar vendors no reconocidos (oportunidad para mejorar regex)
bq query --use_legacy_sql=false "
SELECT raw_log, COUNT(*) c
FROM \`PROJECT.network_logs.raw_logs\`
WHERE DATE(ingest_timestamp) = CURRENT_DATE()
  AND NOT REGEXP_CONTAINS(raw_log, r'devname=|LEEF:|CEF:|%ASA-|RT_FLOW|SRC=|modsec')
GROUP BY raw_log ORDER BY c DESC LIMIT 20"
```

## Próximos pasos

- [ ] Receptor syslog (Fluent Bit) que tome de las cajas y publique a Pub/Sub
- [ ] Migrar a Storage Write API (50% más barato que streaming inserts)
- [ ] Enriquecimiento GeoIP a la derived table
- [ ] Más vendors en el COALESCE (Aruba, Meraki, Azure NSG, AWS VPC Flow)
