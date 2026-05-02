"""
Parsers compactos para vendors adicionales.
Cada uno sigue el mismo patrón: matches() + parse() con extracción de campos.
"""
import re
from .base import BaseParser, ParsedLog, register
from ._helpers import parse_kv, parse_leef_header, safe_int, now_utc


@register
class WatchguardLeefParser(BaseParser):
    vendor = "watchguard"
    product = "firebox"
    priority = 25

    def matches(self, raw_log: str) -> bool:
        return "LEEF:" in raw_log and "WatchGuard" in raw_log

    def parse(self, raw_log: str) -> ParsedLog:
        leef = parse_leef_header(raw_log) or {"fields": {}}
        f = leef.get("fields", {})
        return ParsedLog(
            ingest_timestamp=now_utc(), vendor=self.vendor, product=self.product, raw_log=raw_log,
            source_ip=f.get("src"), source_port=safe_int(f.get("srcPort")),
            dest_ip=f.get("dst"), dest_port=safe_int(f.get("dstPort")),
            protocol=f.get("proto"), action=f.get("disp"),
            rule_name=f.get("policy"), user=f.get("src_user"),
            bytes_sent=safe_int(f.get("sent_bytes")),
            bytes_received=safe_int(f.get("rcvd_bytes")),
            extra={k: v for k, v in f.items() if k in ("app", "geo_src", "geo_dst", "sni")},
        )


@register
class CheckpointKvParser(BaseParser):
    """Check Point en formato key:value (no CEF)."""
    vendor = "checkpoint"
    product = "smart-1"
    priority = 35

    def matches(self, raw_log: str) -> bool:
        # Patrón de CP no-CEF: tiene "Action: " + "src:" + "ProductFamily: Network"
        return ("ProductName" in raw_log and "ProductFamily" in raw_log) and "CEF:" not in raw_log

    def parse(self, raw_log: str) -> ParsedLog:
        # CP usa formato "key: value;" o "key=value"
        kv = {}
        for match in re.finditer(r'(\w+)[:=]\s*([^;\s]+)', raw_log):
            kv[match.group(1)] = match.group(2).strip('"')
        return ParsedLog(
            ingest_timestamp=now_utc(), vendor=self.vendor, product=self.product, raw_log=raw_log,
            source_ip=kv.get("src"), dest_ip=kv.get("dst"),
            protocol=kv.get("proto"), action=kv.get("action"),
            rule_name=kv.get("rule") or kv.get("rule_uid"),
            extra={k: v for k, v in kv.items() if k in ("inzone", "outzone", "service_id")},
        )


@register
class CiscoAsaParser(BaseParser):
    vendor = "cisco"
    product = "asa"
    priority = 40

    _DETECT_RE = re.compile(r'%ASA-\d-\d+|%FTD-\d-\d+')
    # ASA usa varios formatos. Los más comunes:
    #   "from outside:1.2.3.4/52311 to inside:5.6.7.8/443"
    #   "for outside:1.2.3.4/443 ... to inside:5.6.7.8/52311"
    #   "src outside:1.2.3.4/52311 dst inside:5.6.7.8/443"
    _CONN_RE = re.compile(
        r'(?:from|for|src)\s+\S+:(\d{1,3}(?:\.\d{1,3}){3})/(\d+)'
        r'.*?(?:to|dst)\s+\S+:(\d{1,3}(?:\.\d{1,3}){3})/(\d+)'
    )

    def matches(self, raw_log: str) -> bool:
        return bool(self._DETECT_RE.search(raw_log))

    def parse(self, raw_log: str) -> ParsedLog:
        msg_id_match = re.search(r'%(?:ASA|FTD)-\d-(\d+)', raw_log)
        conn_match = self._CONN_RE.search(raw_log)
        action = "deny" if "denied" in raw_log.lower() or "deny" in raw_log.lower() else \
                 "allow" if "built" in raw_log.lower() or "permitted" in raw_log.lower() else None
        return ParsedLog(
            ingest_timestamp=now_utc(), vendor=self.vendor, product=self.product, raw_log=raw_log,
            source_ip=conn_match.group(1) if conn_match else None,
            source_port=safe_int(conn_match.group(2)) if conn_match else None,
            dest_ip=conn_match.group(3) if conn_match else None,
            dest_port=safe_int(conn_match.group(4)) if conn_match else None,
            action=action,
            extra={"asa_msg_id": msg_id_match.group(1) if msg_id_match else None},
        )


@register
class JuniperSrxParser(BaseParser):
    vendor = "juniper"
    product = "srx"
    priority = 45

    def matches(self, raw_log: str) -> bool:
        return "RT_FLOW" in raw_log or "source-address=" in raw_log

    def parse(self, raw_log: str) -> ParsedLog:
        kv = parse_kv(raw_log)
        return ParsedLog(
            ingest_timestamp=now_utc(), vendor=self.vendor, product=self.product, raw_log=raw_log,
            source_ip=kv.get("source-address") or kv.get("src-addr"),
            source_port=safe_int(kv.get("source-port")),
            dest_ip=kv.get("destination-address") or kv.get("dst-addr"),
            dest_port=safe_int(kv.get("destination-port")),
            protocol=kv.get("protocol-id") or kv.get("protocol"),
            user=kv.get("username"),
            rule_name=kv.get("policy-name"),
        )


@register
class SonicwallParser(BaseParser):
    vendor = "sonicwall"
    product = "nsa"
    priority = 50

    def matches(self, raw_log: str) -> bool:
        # SonicWall: "id=firewall sn=XXX time=..."
        return re.search(r'\bid=firewall\b.*\bsn=', raw_log) is not None

    def parse(self, raw_log: str) -> ParsedLog:
        kv = parse_kv(raw_log)
        # SonicWall pone src=IP:port:iface, dst=IP:port:iface
        src_ip, src_port = None, None
        if "src" in kv:
            parts = kv["src"].split(":")
            src_ip = parts[0] if parts else None
            src_port = safe_int(parts[1]) if len(parts) > 1 else None
        dst_ip, dst_port = None, None
        if "dst" in kv:
            parts = kv["dst"].split(":")
            dst_ip = parts[0] if parts else None
            dst_port = safe_int(parts[1]) if len(parts) > 1 else None
        return ParsedLog(
            ingest_timestamp=now_utc(), vendor=self.vendor, product=self.product, raw_log=raw_log,
            source_ip=src_ip, source_port=src_port,
            dest_ip=dst_ip, dest_port=dst_port,
            protocol=kv.get("proto"), action=kv.get("msg"),
            user=kv.get("user"),
            extra={"event_id": kv.get("m"), "sn": kv.get("sn")},
        )


@register
class IptablesParser(BaseParser):
    """Linux iptables/Netfilter — formato SRC=, DST= en mayúsculas."""
    vendor = "linux"
    product = "iptables"
    priority = 60

    def matches(self, raw_log: str) -> bool:
        return "SRC=" in raw_log and "DST=" in raw_log and "PROTO=" in raw_log

    def parse(self, raw_log: str) -> ParsedLog:
        kv = parse_kv(raw_log)
        # Detectar acción del prefijo del kernel: [UFW BLOCK], [DROP], etc.
        action = None
        if re.search(r'\[.*BLOCK.*\]|\[.*DROP.*\]', raw_log, re.IGNORECASE):
            action = "deny"
        elif re.search(r'\[.*ACCEPT.*\]|\[.*ALLOW.*\]', raw_log, re.IGNORECASE):
            action = "allow"
        return ParsedLog(
            ingest_timestamp=now_utc(), vendor=self.vendor, product=self.product, raw_log=raw_log,
            source_ip=kv.get("SRC"), source_port=safe_int(kv.get("SPT")),
            dest_ip=kv.get("DST"), dest_port=safe_int(kv.get("DPT")),
            protocol=kv.get("PROTO"), action=action,
        )
