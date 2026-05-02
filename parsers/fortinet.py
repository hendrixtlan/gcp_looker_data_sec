"""Parser para Fortinet FortiGate (formato key=value clásico)."""
import re
from datetime import datetime, timezone
from .base import BaseParser, ParsedLog, register
from ._helpers import parse_kv, safe_int, now_utc


@register
class FortinetParser(BaseParser):
    vendor = "fortinet"
    product = "fortigate"
    priority = 10  # muy específico, va temprano

    # Heurística de detección: tiene devname="FGT..." o devid="FG..." o srcip= sin pipes alrededor
    _DETECT_RE = re.compile(r'devname="?FG[^"]*"?|devid="?FG[A-Z0-9]+"?|\bsrcip=\d')

    def matches(self, raw_log: str) -> bool:
        return bool(self._DETECT_RE.search(raw_log))

    def parse(self, raw_log: str) -> ParsedLog:
        kv = parse_kv(raw_log)

        # Fortinet usa eventtime en nanosegundos epoch o date+time separados
        event_ts = None
        if "date" in kv and "time" in kv:
            try:
                # Formato: date=2026-04-01 time=14:22:10
                tz = kv.get("tz", "+0000").replace('"', '')
                event_ts = datetime.strptime(
                    f"{kv['date']} {kv['time']} {tz}",
                    "%Y-%m-%d %H:%M:%S %z"
                )
            except ValueError:
                pass

        return ParsedLog(
            ingest_timestamp=now_utc(),
            vendor=self.vendor,
            product=self.product,
            raw_log=raw_log,
            event_timestamp=event_ts,
            source_ip=kv.get("srcip"),
            source_port=safe_int(kv.get("srcport")),
            dest_ip=kv.get("dstip"),
            dest_port=safe_int(kv.get("dstport")),
            protocol=kv.get("proto") or kv.get("service"),
            action=kv.get("action"),
            rule_name=kv.get("policyid"),
            user=kv.get("user") or kv.get("srcuser"),
            bytes_sent=safe_int(kv.get("sentbyte")),
            bytes_received=safe_int(kv.get("rcvdbyte")),
            hostname=kv.get("devname", "").strip('"') or None,
            severity=kv.get("level"),
            message=kv.get("msg", "").strip('"') or None,
            extra={
                k: v for k, v in kv.items()
                if k in ("subtype", "eventtype", "policytype", "srccountry",
                         "dstcountry", "hostname", "url", "profile")
            },
        )
