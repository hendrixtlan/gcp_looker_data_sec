"""Pruebas de los parsers con muestras reales de cada vendor."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers import parse_log


SAMPLES = {
    "fortinet": (
        '<188>date=2026-04-01 time=14:22:10 devname="FGT" devid="FG100E0AB12345678" '
        'eventtime=1775001234567890000 tz="-0500" logid="03108643544" type="utm" '
        'subtype="webfilter" eventtype="urlfilter" level="warning" vd="root" '
        'urlfilteridx=12 urlfilterlist="Auto-webfilter01" policyid=999 '
        'srcip=192.168.10.25 srcport=52311 srccountry="Private" srcintf="port3" '
        'dstip=203.0.113.10 dstport=443 dstcountry="United States" dstintf="port1" '
        'proto=6 service="HTTPS" hostname="online.office.com" profile="Dotsite" '
        'action="blocked" reqtype="direct" url="https://online.office.com/login" '
        'sentbyte=2048 rcvdbyte=0 direction="outgoing" '
        'msg="URL was blocked because it is in the URL filter list"'
    ),
    "paloalto": (
        '<14>1 2026-04-05T09:15:45-05:00 PA-001 - - - - LEEF:2.0|Palo Alto Networks|'
        'PAN-OS Syslog Integration|11.2.0|allow|x7C|cat=TRAFFIC|devTime=Apr 05 2026 14:15:45 GMT|'
        'SerialNumber=47949163|Subtype=end|src=10.10.20.5|dst=1.1.1.1|'
        'srcPostNAT=198.51.100.45|dstPostNAT=1.1.1.1|RuleName=Internet-Rule|'
        'usrName=nniowmp.jytf|Application=dns-base|VirtualSystem=vsys1|'
        'SourceZone=INSIDE|DestinationZone=INTERNET|srcPort=55321|dstPort=53|'
        'proto=udp|totalBytes=512|srcBytes=220|dstBytes=292|DeviceName=PA-uPt-001'
    ),
    "modsecurity": (
        'modsec 2026/02/10 11:42:33 [info] 06239#76498: *006523171 ModSecurity: '
        'Warning. Matched "Operator `Rx\' with parameter `^$\' against variable '
        '`REQUEST_HEADERS:user-agent\' (Value: `` ) [file "/nginx/modset/modsecurity-'
        'crs/rules/REQUEST-512-PROTOCOL-ENFORCEMENT.conf"] [line "692"] [id "944287"] '
        '[rev ""] [msg "Empty User Agent Header"] [data ""] [severity "5"] '
        '[ver "OWASP_CRS/4.0.0"] [maturity "0"] [accuracy "0"] [tag "application-multi"] '
        '[tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] '
        '[tag "paranoia-level/1"] [tag "OWASP_CRS"] [hostname "10.0.0.20"] '
        '[uri "/api/v1/product/search"] [unique_id "98511376895431.89051234"] '
        '[ref "o0,0v1482,0"], client: 198.51.100.100, server: api.dif.cl, '
        'request: "POST /api/v1/product/search HTTP/2.0", host: "api.dif.cl"'
    ),
    "watchguard": (
        '<142>Feb 25 12:49:50 hostname LEEF:1.0|WatchGuard|XTM|12.6.2.B631387|2CFF0000|'
        'serial=ABC123 policy=HTTPS-proxy-00 disp=Allow in_if=Trusted out_if=Fiber '
        'proto=tcp src=192.168.1.222 srcPort=58152 dst=34.228.135.247 dstPort=443 '
        'sent_bytes=700 rcvd_bytes=7515'
    ),
    "iptables": (
        'Apr 15 22:10:33 myhost kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... '
        'SRC=203.0.113.50 DST=10.0.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12345 '
        'PROTO=TCP SPT=43210 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0'
    ),
    "cisco_asa": (
        '<166>%ASA-6-302013: Built outbound TCP connection 12345 for outside:'
        '203.0.113.10/443 (203.0.113.10/443) to inside:192.168.1.50/52311 '
        '(192.168.1.50/52311)'
    ),
    "checkpoint_cef": (
        'CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Accept|Accept|Unknown|'
        'act=Accept dst=52.173.84.157 src=192.168.101.100 spt=49363 dpt=443 '
        'proto=6 rule_uid=9e5e6e74-aa9a-4693-b9fe-53712dd27bea '
        'sourceTranslatedAddress=192.168.103.254'
    ),
    "unknown": (
        'Some weird log format that nobody recognizes from a custom appliance'
    ),
}


def test_all():
    print(f"{'='*80}")
    print(f"{'VENDOR':<15} | {'PRODUCT':<15} | {'SOURCE_IP':<18} | {'DEST_IP':<18} | ACTION")
    print(f"{'='*80}")
    all_pass = True
    for name, log in SAMPLES.items():
        result = parse_log(log)
        status = "✓" if result.vendor != "unknown" or name == "unknown" else "✗"
        print(f"{status} {result.vendor:<13} | {result.product:<15} | "
              f"{str(result.source_ip):<18} | {str(result.dest_ip):<18} | {result.action}")
        if name != "unknown" and result.vendor == "unknown":
            print(f"   FALLO: log de {name} no fue reconocido")
            all_pass = False
        # Verificar que to_bq_row no tira errores
        try:
            row = result.to_bq_row()
            assert isinstance(row, dict)
        except Exception as e:
            print(f"   to_bq_row falló: {e}")
            all_pass = False

    print(f"{'='*80}")
    print(f"Resultado: {'✓ TODO OK' if all_pass else '✗ HAY FALLOS'}")
    return all_pass


if __name__ == "__main__":
    success = test_all()
    sys.exit(0 if success else 1)
