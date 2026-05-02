"""Parser para ModSecurity (nginx/Apache WAF)."""
import re
from datetime import datetime, timezone
from .base import BaseParser, ParsedLog, register
from ._helpers import now_utc


@register
class ModSecurityParser(BaseParser):
    vendor = "modsecurity"
    product = "modsecurity"
    priority = 30

    _DETECT_RE = re.compile(r'\bmodsec\b|ModSecurity|OWASP_CRS')

    # ModSecurity usa formato de bracket: [tag "value"]
    _BRACKET_RE = re.compile(r'\[(\w+)\s+"([^"]*)"\]')
    _CLIENT_RE = re.compile(r'client:\s*(\d{1,3}(?:\.\d{1,3}){3})')
    _HOST_RE = re.compile(r'host:\s*"?([^",\s]+)"?')
    _REQUEST_RE = re.compile(r'request:\s*"([A-Z]+)\s+([^\s"]+)')
    _SERVER_RE = re.compile(r'server:\s*([^,\s]+)')

    def matches(self, raw_log: str) -> bool:
        return bool(self._DETECT_RE.search(raw_log))

    def parse(self, raw_log: str) -> ParsedLog:
        # Tags entre brackets: [id "944287"], [msg "..."], [severity "5"]
        bracket_fields = {k: v for k, v in self._BRACKET_RE.findall(raw_log)}

        client_match = self._CLIENT_RE.search(raw_log)
        host_match = self._HOST_RE.search(raw_log)
        request_match = self._REQUEST_RE.search(raw_log)

        # ModSecurity timestamp: 2026/02/10 11:42:33
        event_ts = None
        ts_match = re.search(r'(\d{4})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})', raw_log)
        if ts_match:
            try:
                event_ts = datetime(
                    int(ts_match.group(1)), int(ts_match.group(2)), int(ts_match.group(3)),
                    int(ts_match.group(4)), int(ts_match.group(5)), int(ts_match.group(6)),
                    tzinfo=timezone.utc,
                )
            except ValueError:
                pass

        return ParsedLog(
            ingest_timestamp=now_utc(),
            vendor=self.vendor,
            product=self.product,
            raw_log=raw_log,
            event_timestamp=event_ts,
            source_ip=client_match.group(1) if client_match else None,
            hostname=host_match.group(1) if host_match else None,
            severity=bracket_fields.get("severity"),
            rule_name=bracket_fields.get("id"),
            message=bracket_fields.get("msg"),
            action="blocked" if "denied" in raw_log.lower() else "warning",
            extra={
                "uri": bracket_fields.get("uri"),
                "method": request_match.group(1) if request_match else None,
                "request_path": request_match.group(2) if request_match else None,
                "owasp_tags": [v for k, v in self._BRACKET_RE.findall(raw_log) if k == "tag"],
                "matched_data": bracket_fields.get("data"),
            },
        )
