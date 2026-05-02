# =============================================================================
# View: raw_logs
# =============================================================================
# Tabla source: `network_logs.raw_logs` con SOLO 2 columnas:
#   - ingest_timestamp (TIMESTAMP, partición diaria)
#   - raw_log (STRING, syslog crudo sin tocar)
#
# DISEÑO INTENCIONAL: todo el parseo vive en LookML.
# Ventajas:
#   - Analistas iteran regex sin redeploys de pipelines
#   - Soportar un vendor nuevo = agregar un patrón al COALESCE, no tocar Python
#   - Toda la lógica de parseo es auditable en un solo lugar (este archivo)
#
# Costo de este diseño: las queries son 10-50× más caras que con columnas
# tipadas. Mitigaciones:
#   1. always_filter en el explore fuerza filtro temporal (limita partition scan)
#   2. derived_table materializada (al final del archivo) precomputa los regex
#      con scheduled refresh, así dashboards consultan datos ya parseados
#
# REFERENCIA RÁPIDA — keys de IP origen por vendor:
#   srcip=         Fortinet
#   |src=...|      Palo Alto LEEF, WatchGuard LEEF
#   src=           CEF estándar (Check Point, F5 ASM, ArcSight, WatchGuard syslog)
#   src_ip=        WatchGuard syslog nativo, Sophos
#   source-address Juniper SRX
#   src=...:       SonicWall (con puerto adjunto)
#   SRC=           iptables/Netfilter (mayúsculas)
#   client:        nginx, ModSecurity, Apache
#   from X:IP/port Cisco ASA
# =============================================================================

view: raw_logs {
  sql_table_name: `@{GCP_PROJECT}.@{BQ_DATASET}.raw_logs` ;;

  # ==========================================================================
  # PRIMARY KEY (sintética: no hay id único en logs crudos)
  # ==========================================================================
  dimension: pk {
    primary_key: yes
    hidden: yes
    type: string
    sql: CONCAT(
      CAST(${TABLE}.ingest_timestamp AS STRING), '|',
      TO_HEX(MD5(${TABLE}.raw_log))
    ) ;;
  }

  # ==========================================================================
  # TIMESTAMPS
  # ==========================================================================
  dimension_group: ingest {
    type: time
    description: "Cuándo el log entró a BigQuery (campo de partición)"
    timeframes: [raw, time, hour, date, week, month, quarter, year]
    sql: ${TABLE}.ingest_timestamp ;;
  }

  # ==========================================================================
  # RAW LOG
  # ==========================================================================
  dimension: raw_log {
    type: string
    description: "Log syslog original sin procesar"
    sql: ${TABLE}.raw_log ;;
  }

  # ==========================================================================
  # DETECCIÓN DE VENDOR (por patrones distintivos del log)
  # ==========================================================================
  # Esta dimension permite filtrar/agrupar por fabricante. Útil para
  # dashboards comparativos y para validar cobertura del parser.
  # ==========================================================================
  dimension: vendor {
    type: string
    description: "Fabricante detectado a partir de patrones en el log"
    sql: CASE
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'devname="?FG|devid="?FG[A-Z0-9]')
        THEN 'fortinet'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'LEEF:[\d.]+\|Palo Alto Networks')
        THEN 'paloalto'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'LEEF:[\d.]+\|WatchGuard')
        THEN 'watchguard'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'CEF:\d+\|Check Point')
        THEN 'checkpoint'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'%(?:ASA|FTD)-\d-\d+')
        THEN 'cisco'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'RT_FLOW|source-address=')
        THEN 'juniper'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'\bid=firewall\b.*\bsn=')
        THEN 'sonicwall'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'SRC=\d.*DST=\d.*PROTO=')
        THEN 'iptables'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'\bmodsec\b|ModSecurity|OWASP_CRS')
        THEN 'modsecurity'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'CEF:\d+\|')
        THEN 'cef-generic'
      WHEN REGEXP_CONTAINS(${TABLE}.raw_log, r'LEEF:[\d.]+\|')
        THEN 'leef-generic'
      ELSE 'unknown'
    END ;;
  }

  # ==========================================================================
  # IP ORIGEN — COALESCE de regex por vendor
  # ==========================================================================
  # ORDEN: los patrones más específicos van primero. Por ejemplo, `srcip=` es
  # inequívoco (solo Fortinet), mientras que `src=` aparece en 5+ vendors.
  # Si pones `src=` primero, captura logs de Fortinet por error.
  #
  # Sintaxis BigQuery (motor RE2):
  #   - NO usar `\b` (word boundary) — no soportado, da error
  #   - Usar `(?:^|\s)` como equivalente práctico
  #   - r'...' = raw string literal (no necesitas escapar contrabarras)
  # ==========================================================================
  dimension: source_ip {
    type: string
    description: "IP de origen extraída del raw_log con regex multi-vendor"
    sql: COALESCE(
      -- 1. Fortinet: srcip=192.168.1.1
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:^|\s)srcip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),

      -- 2. iptables / ufw: SRC=1.2.3.4 (mayúsculas)
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:^|\s)SRC=([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),

      -- 3. WatchGuard syslog / Sophos: src_ip="1.2.3.4"
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'src_ip="?([0-9]{1,3}(?:\.[0-9]{1,3}){3})"?'),

      -- 4. Juniper SRX: source-address="1.2.3.4"
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'source-address="?([0-9]{1,3}(?:\.[0-9]{1,3}){3})"?'),

      -- 5. SonicWall: src=1.2.3.4:port:interface
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:^|\s)src=([0-9]{1,3}(?:\.[0-9]{1,3}){3}):'),

      -- 6. LEEF entre pipes: |src=1.2.3.4|  (Palo Alto LEEF, WatchGuard LEEF)
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'\|src=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\|'),

      -- 7. CEF estándar: src=1.2.3.4 (Check Point, F5 ASM, ArcSight)
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:^|\s)src=([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:\s|$)'),

      -- 8. Check Point formato espacio: "src: 1.2.3.4"
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'src:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),

      -- 9. Cisco ASA/FTD: "from outside:1.2.3.4/port" o "for outside:1.2.3.4/port"
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:from|for|src)\s+\S+:([0-9]{1,3}(?:\.[0-9]{1,3}){3})/'),

      -- 10. nginx / ModSecurity / Apache: client: 1.2.3.4
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'client:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),

      -- 11. JSON estilo AWS / Azure: "srcaddr":"1.2.3.4"
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'"(?:srcaddr|sourceAddress|src_addr)":\s*"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"')
    ) ;;

    # Links externos: clic en cualquier IP abre la consulta en estos sitios
    link: {
      label: "Buscar en AbuseIPDB"
      url: "https://www.abuseipdb.com/check/{{ value }}"
      icon_url: "https://www.abuseipdb.com/favicon.ico"
    }
    link: {
      label: "Buscar en VirusTotal"
      url: "https://www.virustotal.com/gui/ip-address/{{ value }}"
    }
  }

  # ==========================================================================
  # IP DESTINO (mismo patrón que source_ip)
  # ==========================================================================
  dimension: dest_ip {
    type: string
    description: "IP destino extraída del raw_log"
    sql: COALESCE(
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:^|\s)dstip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),                 -- Fortinet
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:^|\s)DST=([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),                   -- iptables
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'dst_ip="?([0-9]{1,3}(?:\.[0-9]{1,3}){3})"?'),                    -- WatchGuard/Sophos
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'destination-address="?([0-9]{1,3}(?:\.[0-9]{1,3}){3})"?'),       -- Juniper
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:^|\s)dst=([0-9]{1,3}(?:\.[0-9]{1,3}){3}):'),                  -- SonicWall
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'\|dst=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\|'),                       -- LEEF
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:^|\s)dst=([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:\s|$)'),           -- CEF
      REGEXP_EXTRACT(${TABLE}.raw_log,
        r'(?:to|dst)\s+\S+:([0-9]{1,3}(?:\.[0-9]{1,3}){3})/')              -- Cisco ASA
    ) ;;
  }

  # ==========================================================================
  # PUERTOS
  # ==========================================================================
  dimension: source_port {
    type: number
    sql: SAFE_CAST(COALESCE(
      REGEXP_EXTRACT(${TABLE}.raw_log, r'srcport=(\d+)'),                  -- Fortinet
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\bSPT=(\d+)'),                    -- iptables
      REGEXP_EXTRACT(${TABLE}.raw_log, r'src_port="?(\d+)"?'),             -- WatchGuard
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\|srcPort=(\d+)\|'),              -- LEEF
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\bspt=(\d+)'),                    -- CEF
      REGEXP_EXTRACT(${TABLE}.raw_log, r'(?:from|src)\s+\S+:[0-9.]+/(\d+)') -- Cisco
    ) AS INT64) ;;
  }

  dimension: dest_port {
    type: number
    sql: SAFE_CAST(COALESCE(
      REGEXP_EXTRACT(${TABLE}.raw_log, r'dstport=(\d+)'),
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\bDPT=(\d+)'),
      REGEXP_EXTRACT(${TABLE}.raw_log, r'dst_port="?(\d+)"?'),
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\|dstPort=(\d+)\|'),
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\bdpt=(\d+)'),
      REGEXP_EXTRACT(${TABLE}.raw_log, r'(?:to|dst)\s+\S+:[0-9.]+/(\d+)')
    ) AS INT64) ;;
  }

  # Categorización de puerto destino
  dimension: dest_port_category {
    type: string
    sql: CASE
      WHEN ${dest_port} IN (80, 8080) THEN 'HTTP'
      WHEN ${dest_port} IN (443, 8443) THEN 'HTTPS'
      WHEN ${dest_port} = 22 THEN 'SSH'
      WHEN ${dest_port} = 53 THEN 'DNS'
      WHEN ${dest_port} = 3389 THEN 'RDP'
      WHEN ${dest_port} IN (25, 587, 465) THEN 'SMTP'
      WHEN ${dest_port} BETWEEN 1 AND 1023 THEN 'Well-known'
      WHEN ${dest_port} BETWEEN 1024 AND 49151 THEN 'Registered'
      WHEN ${dest_port} BETWEEN 49152 AND 65535 THEN 'Ephemeral'
      ELSE 'Unknown'
    END ;;
  }

  # ==========================================================================
  # ACCIÓN (allow / block / drop)
  # ==========================================================================
  dimension: action_raw {
    type: string
    description: "Texto de acción tal como aparece en el log"
    sql: COALESCE(
      REGEXP_EXTRACT(${TABLE}.raw_log, r'action="?([a-zA-Z]+)"?'),         -- Fortinet, CEF
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\bdisp=([a-zA-Z]+)'),             -- WatchGuard LEEF
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\bact=([a-zA-Z]+)')               -- CEF
    ) ;;
  }

  # Normalización: las muchas formas de decir "bloqueado" o "permitido"
  dimension: action_normalized {
    type: string
    description: "Acción normalizada: allowed / blocked / other"
    sql: CASE
      WHEN LOWER(${action_raw}) IN ('allow', 'accept', 'permit', 'permitted', 'pass', 'built')
        THEN 'allowed'
      WHEN LOWER(${action_raw}) IN ('deny', 'denied', 'block', 'blocked', 'drop', 'dropped', 'reject')
        THEN 'blocked'
      WHEN REGEXP_CONTAINS(LOWER(${TABLE}.raw_log), r'\b(?:deny|denied|block|blocked|drop|dropped|reject)\b')
        THEN 'blocked'
      WHEN REGEXP_CONTAINS(LOWER(${TABLE}.raw_log), r'\b(?:allow|accept|permit|permitted|pass|built)\b')
        THEN 'allowed'
      ELSE 'other'
    END ;;
  }

  dimension: is_blocked {
    type: yesno
    sql: ${action_normalized} = 'blocked' ;;
  }

  # ==========================================================================
  # PROTOCOLO
  # ==========================================================================
  dimension: protocol {
    type: string
    sql: UPPER(COALESCE(
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\bproto=([a-zA-Z0-9]+)'),
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\bPROTO=([A-Z]+)'),
      REGEXP_EXTRACT(${TABLE}.raw_log, r'\bprotocol="?([a-zA-Z]+)"?')
    )) ;;
  }

  # ==========================================================================
  # MEASURES (agregaciones)
  # ==========================================================================
  measure: count {
    type: count
    description: "Total de eventos"
    drill_fields: [ingest_time, vendor, source_ip, dest_ip, action_normalized, raw_log]
  }

  measure: distinct_source_ips {
    type: count_distinct
    description: "IPs origen únicas"
    sql: ${source_ip} ;;
    drill_fields: [source_ip, count]
  }

  measure: distinct_dest_ips {
    type: count_distinct
    sql: ${dest_ip} ;;
  }

  measure: blocked_count {
    type: count
    description: "Total de eventos bloqueados"
    filters: [action_normalized: "blocked"]
  }

  measure: allowed_count {
    type: count
    filters: [action_normalized: "allowed"]
  }

  measure: block_rate {
    type: number
    description: "% de tráfico bloqueado"
    sql: SAFE_DIVIDE(${blocked_count}, ${count}) ;;
    value_format_name: percent_2
  }

  measure: unknown_vendor_count {
    type: count
    description: "Logs no reconocidos (oportunidad para ajustar regex)"
    filters: [vendor: "unknown"]
  }
}


# =============================================================================
# DERIVED TABLE MATERIALIZADA — opcional pero RECOMENDADA
# =============================================================================
# Esta vista precomputa los regex con scheduled refresh cada hora. Los
# dashboards de Looker apuntan a este view (`raw_logs_parsed`) en vez de
# `raw_logs`, lo que reduce el costo de query a niveles normales.
#
# Trade-off: los datos tienen latencia de hasta 1 hora.
# Si necesitas tiempo real, los dashboards consultan `raw_logs` directamente
# (caro) y los reportes históricos consultan `raw_logs_parsed` (barato).
# =============================================================================

view: raw_logs_parsed {
  derived_table: {
    sql:
      SELECT
        ingest_timestamp,
        raw_log,
        -- Vendor
        CASE
          WHEN REGEXP_CONTAINS(raw_log, r'devname="?FG') THEN 'fortinet'
          WHEN REGEXP_CONTAINS(raw_log, r'LEEF:[\d.]+\|Palo Alto Networks') THEN 'paloalto'
          WHEN REGEXP_CONTAINS(raw_log, r'LEEF:[\d.]+\|WatchGuard') THEN 'watchguard'
          WHEN REGEXP_CONTAINS(raw_log, r'CEF:\d+\|Check Point') THEN 'checkpoint'
          WHEN REGEXP_CONTAINS(raw_log, r'%(?:ASA|FTD)-\d-\d+') THEN 'cisco'
          WHEN REGEXP_CONTAINS(raw_log, r'\bmodsec\b|OWASP_CRS') THEN 'modsecurity'
          ELSE 'other'
        END AS vendor,
        -- Source IP (mismo COALESCE que arriba)
        COALESCE(
          REGEXP_EXTRACT(raw_log, r'(?:^|\s)srcip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),
          REGEXP_EXTRACT(raw_log, r'(?:^|\s)SRC=([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),
          REGEXP_EXTRACT(raw_log, r'src_ip="?([0-9]{1,3}(?:\.[0-9]{1,3}){3})"?'),
          REGEXP_EXTRACT(raw_log, r'\|src=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\|'),
          REGEXP_EXTRACT(raw_log, r'(?:^|\s)src=([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:\s|$)'),
          REGEXP_EXTRACT(raw_log, r'client:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})')
        ) AS source_ip,
        COALESCE(
          REGEXP_EXTRACT(raw_log, r'(?:^|\s)dstip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),
          REGEXP_EXTRACT(raw_log, r'(?:^|\s)DST=([0-9]{1,3}(?:\.[0-9]{1,3}){3})'),
          REGEXP_EXTRACT(raw_log, r'\|dst=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\|'),
          REGEXP_EXTRACT(raw_log, r'(?:^|\s)dst=([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:\s|$)')
        ) AS dest_ip
      FROM `@{GCP_PROJECT}.@{BQ_DATASET}.raw_logs`
      WHERE ingest_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
    ;;
    datagroup_trigger: hourly_refresh
    partition_keys: ["ingest_timestamp"]
    cluster_keys: ["vendor", "source_ip"]
  }

  dimension: pk {
    primary_key: yes
    hidden: yes
    sql: CONCAT(CAST(${TABLE}.ingest_timestamp AS STRING), '|', TO_HEX(MD5(${TABLE}.raw_log))) ;;
  }

  dimension_group: ingest {
    type: time
    timeframes: [raw, time, hour, date, week, month]
    sql: ${TABLE}.ingest_timestamp ;;
  }

  dimension: vendor { sql: ${TABLE}.vendor ;; }
  dimension: source_ip { sql: ${TABLE}.source_ip ;; }
  dimension: dest_ip { sql: ${TABLE}.dest_ip ;; }
  dimension: raw_log { sql: ${TABLE}.raw_log ;; }

  measure: count { type: count }
  measure: distinct_source_ips { type: count_distinct sql: ${source_ip} ;; }
}
