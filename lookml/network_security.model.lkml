# =============================================================================
# Model: network_security
# =============================================================================

connection: "gcp_logs"

include: "/views/*.view.lkml"

# Datagroup que dispara el refresh del derived table materializado.
# `max_cache_age` controla cuándo Looker considera que su caché está vencida.
# `sql_trigger` es la query que detecta si hay datos nuevos (refresh real).
datagroup: hourly_refresh {
  max_cache_age: "1 hour"
  sql_trigger: SELECT FLOOR(UNIX_SECONDS(CURRENT_TIMESTAMP()) / 3600) ;;
}

# Explore sobre la tabla cruda — caro, solo para investigación puntual
explore: raw_logs {
  label: "Logs Crudos (investigación)"
  description: "Acceso directo a logs sin parsear. Caro: usar solo con filtros estrictos"

  always_filter: {
    filters: [ingest_date: "1 hour"]   # filtro muy estrecho, esto escanea todo
  }
}

# Explore sobre la tabla parseada y materializada — barato, para dashboards
explore: raw_logs_parsed {
  label: "Logs Parseados (dashboards)"
  description: "Tabla con regex precomputados. Refresh cada hora."
  persist_with: hourly_refresh

  always_filter: {
    filters: [ingest_date: "1 day"]
  }
}
