"""Parser para Palo Alto Networks PAN-OS en formato LEEF."""
from datetime import datetime, timezone
from .base import BaseParser, ParsedLog, register
from ._helpers import parse_leef_header, safe_int, now_utc


@register
class PaloAltoLeefParser(BaseParser):
    vendor = "paloalto"
    product = "pan-os"
    priority = 20

    def matches(self, raw_log: str) -> bool:
        return "LEEF:" in raw_log and "Palo Alto Networks" in raw_log

    def parse(self, raw_log: str) -> ParsedLog:
        leef = parse_leef_header(raw_log)
        if not leef:
            # No debería pasar si matches() pasó, pero por seguridad
            return ParsedLog(
                ingest_timestamp=now_utc(),
                vendor=self.vendor, product=self.product, raw_log=raw_log,
            )

        f = leef["fields"]

        # Palo Alto manda devTime en formato "Apr 05 2026 14:15:45 GMT"
        event_ts = None
        if "devTime" in f:
            try:
                event_ts = datetime.strptime(f["devTime"], "%b %d %Y %H:%M:%S %Z")
                event_ts = event_ts.replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        return ParsedLog(
            ingest_timestamp=now_utc(),
            vendor=self.vendor,
            product=self.product,
            raw_log=raw_log,
            event_timestamp=event_ts,
            source_ip=f.get("src"),
            source_port=safe_int(f.get("srcPort")),
            dest_ip=f.get("dst"),
            dest_port=safe_int(f.get("dstPort")),
            protocol=f.get("proto"),
            action=f.get("cat"),  # en PA, "cat" es la categoría/acción (TRAFFIC, THREAT...)
            rule_name=f.get("RuleName"),
            user=f.get("usrName") or f.get("srcUser"),
            bytes_sent=safe_int(f.get("srcBytes")),
            bytes_received=safe_int(f.get("dstBytes")),
            hostname=f.get("DeviceName"),
            extra={
                k: v for k, v in f.items()
                if k in ("Application", "VirtualSystem", "SourceZone",
                         "DestinationZone", "URLCategory", "SessionID",
                         "srcPostNAT", "dstPostNAT")
            },
        )
