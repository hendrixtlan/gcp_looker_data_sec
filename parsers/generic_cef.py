"""
Parser genérico CEF — fallback para cualquier vendor que use CEF estándar.
Cubre: Check Point (R80+ Log Exporter), F5 BIG-IP ASM, ArcSight, y muchos más.

Tiene priority alta (=80) para que parsers específicos se evalúen primero,
pero atrape lo que ellos no manejen.
"""
from .base import BaseParser, ParsedLog, register
from ._helpers import parse_cef_header, safe_int, now_utc


@register
class GenericCefParser(BaseParser):
    vendor = "cef-generic"
    product = "cef"
    priority = 80  # fallback antes del LEEF genérico

    def matches(self, raw_log: str) -> bool:
        return "CEF:" in raw_log

    def parse(self, raw_log: str) -> ParsedLog:
        cef = parse_cef_header(raw_log)
        if not cef:
            return ParsedLog(
                ingest_timestamp=now_utc(),
                vendor=self.vendor, product=self.product, raw_log=raw_log,
            )

        f = cef["fields"]
        # Detectar el vendor real desde el header CEF y reportarlo
        actual_vendor = cef["vendor"].lower().replace(" ", "_")
        actual_product = cef["product"].lower().replace(" ", "_")

        return ParsedLog(
            ingest_timestamp=now_utc(),
            vendor=actual_vendor,
            product=actual_product,
            raw_log=raw_log,
            # CEF estándar usa src/dst/spt/dpt
            source_ip=f.get("src"),
            source_port=safe_int(f.get("spt")),
            dest_ip=f.get("dst"),
            dest_port=safe_int(f.get("dpt")),
            protocol=f.get("proto"),
            action=f.get("act") or cef.get("name"),
            rule_name=f.get("rule_uid") or f.get("cs1"),
            user=f.get("suser") or f.get("duser"),
            bytes_sent=safe_int(f.get("out")),
            bytes_received=safe_int(f.get("in")),
            severity=cef.get("severity"),
            message=cef.get("name"),
            extra={
                "cef_signature_id": cef.get("signature_id"),
                "source_translated": f.get("sourceTranslatedAddress"),
                "dest_translated": f.get("destinationTranslatedAddress"),
            },
        )
