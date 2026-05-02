"""Utilidades compartidas entre parsers."""
import re
from datetime import datetime, timezone
from typing import Optional

# Regex para IPs IPv4 (suficiente para la mayoría de casos; IPv6 lo agregamos después)
IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def parse_kv(text: str, sep: str = " ") -> dict[str, str]:
    """
    Parsea pares key=value separados por `sep`.
    Soporta valores entre comillas: key="value with spaces"
    """
    result = {}
    # Regex que captura: key=value | key="quoted value" | key='quoted value'
    pattern = re.compile(
        r'(\w[\w.-]*)='
        r'(?:"([^"]*)"|\'([^\']*)\'|([^\s|]*))'
    )
    for match in pattern.finditer(text):
        key = match.group(1)
        # El valor está en el primer grupo no-None de los siguientes 3
        value = match.group(2) or match.group(3) or match.group(4) or ""
        result[key] = value
    return result


def parse_leef_header(raw_log: str) -> Optional[dict]:
    """
    Parsea header LEEF: LEEF:Version|Vendor|Product|Version|EventID|...
    Retorna dict con header + campos del extension parseados como kv.
    """
    leef_match = re.search(
        r'LEEF:([\d.]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.*)',
        raw_log
    )
    if not leef_match:
        return None
    header = {
        "leef_version": leef_match.group(1),
        "vendor": leef_match.group(2),
        "product": leef_match.group(3),
        "version": leef_match.group(4),
        "event_id": leef_match.group(5),
    }
    # El extension puede usar tab (\t) o pipe (|) como separador
    extension = leef_match.group(6)
    # Separamos por pipe primero (más común en CP/PaloAlto LEEF), si no por espacio
    if "|" in extension:
        kv_text = extension.replace("|", " ")
    else:
        kv_text = extension
    header["fields"] = parse_kv(kv_text)
    return header


def parse_cef_header(raw_log: str) -> Optional[dict]:
    """
    Parsea header CEF: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|extension
    """
    cef_match = re.search(
        r'CEF:(\d+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.*)',
        raw_log
    )
    if not cef_match:
        return None
    return {
        "cef_version": cef_match.group(1),
        "vendor": cef_match.group(2),
        "product": cef_match.group(3),
        "version": cef_match.group(4),
        "signature_id": cef_match.group(5),
        "name": cef_match.group(6),
        "severity": cef_match.group(7),
        "fields": parse_kv(cef_match.group(8)),
    }


def safe_int(value: Optional[str]) -> Optional[int]:
    """Convierte a int sin tirar excepción."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
