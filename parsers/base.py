"""
Sistema de parsers basado en registry.

Cada parser declara:
  - vendor: identificador del fabricante
  - product: producto específico (FortiGate, ASA, etc.)
  - matches(raw_log): retorna True si este parser puede manejar el log
  - parse(raw_log): retorna dict con campos extraídos

El orden de los matchers importa: los más específicos van primero.
Por eso usamos `priority` (menor = se evalúa antes).
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ParsedLog:
    """Esquema canónico unificado. Mapea 1:1 a las columnas de BigQuery."""
    # Metadata
    ingest_timestamp: datetime
    vendor: str
    product: str
    raw_log: str

    # Campos comunes de red/seguridad
    event_timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None        # allow / deny / block / drop
    rule_name: Optional[str] = None
    user: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    hostname: Optional[str] = None      # device hostname
    severity: Optional[str] = None
    message: Optional[str] = None

    # Para campos no estándar / específicos del vendor
    extra: dict = field(default_factory=dict)

    def to_bq_row(self) -> dict:
        """Serializa a dict listo para BigQuery (timestamps en ISO 8601)."""
        d = asdict(self)
        for ts_field in ("ingest_timestamp", "event_timestamp"):
            if d[ts_field] is not None:
                d[ts_field] = d[ts_field].isoformat()
        # BQ no acepta dicts arbitrarios en columna; los serializamos como JSON string
        # (la columna `extra` será JSON type en BQ)
        import json
        d["extra"] = json.dumps(d["extra"]) if d["extra"] else None
        return d


class BaseParser(ABC):
    """Interfaz que cada parser de vendor debe implementar."""
    vendor: str = ""
    product: str = ""
    priority: int = 100  # menor = se evalúa antes

    @abstractmethod
    def matches(self, raw_log: str) -> bool:
        """¿Este parser puede manejar este log?"""
        ...

    @abstractmethod
    def parse(self, raw_log: str) -> ParsedLog:
        """Extrae campos del log. Solo se llama si matches() devolvió True."""
        ...


# Registry global. Cada módulo de parser se auto-registra con @register.
_REGISTRY: list[BaseParser] = []


def register(cls):
    """Decorador para registrar un parser."""
    instance = cls()
    _REGISTRY.append(instance)
    # Mantenemos la lista ordenada por prioridad
    _REGISTRY.sort(key=lambda p: p.priority)
    return cls


def get_parsers() -> list[BaseParser]:
    return list(_REGISTRY)


def parse_log(raw_log: str) -> ParsedLog:
    """
    Punto de entrada principal: encuentra el primer parser que matchea
    y retorna el resultado. Si nadie matchea, devuelve un ParsedLog
    con vendor='unknown' (que igual entra a BQ para no perder el dato).
    """
    raw_log = raw_log.strip()
    for parser in _REGISTRY:
        try:
            if parser.matches(raw_log):
                return parser.parse(raw_log)
        except Exception as e:
            # Si un parser falla, no rompemos: lo logueamos y seguimos
            import logging
            logging.warning(
                "Parser %s falló en log (primeros 200 chars: %r): %s",
                parser.__class__.__name__, raw_log[:200], e
            )
            continue

    # Fallback: log no reconocido, lo guardamos crudo para análisis posterior
    return ParsedLog(
        ingest_timestamp=datetime.now(timezone.utc),
        vendor="unknown",
        product="unknown",
        raw_log=raw_log,
    )
