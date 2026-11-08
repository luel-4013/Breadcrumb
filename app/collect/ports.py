"""Native TCP connect scan: open ports, banners, and TLS certificates.

This is a completed-handshake connect() scan, not a raw SYN scan, so it needs
no elevated privileges. The collector uses the scope guard's pinned address for
every connection and emits nmap XML, which Breadcrumb's existing nmap parser
turns into host/port/service entities and ``has_port`` relationships.

A high-risk open service is additionally emitted as nuclei-compatible JSONL so
the normal finding path can file it as a candidate. It is never labeled a
confirmed vulnerability.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import socket
import ssl
import threading
import xml.sax.saxutils as saxutils
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .base import (
    Collector,
    CollectorContext,
    CollectorError,
    CollectorResult,
    PhaseOutput,
    register,
)
from .findings import nuclei_jsonl, nuclei_record

# Port -> (service, speaks TLS immediately). A curated set of ports that
# commonly carry a real service; a 1-65535 sweep is slower and noisier for
# very little extra signal. Keep this list close to Leadline's.
COMMON_PORTS: dict[int, tuple[str, bool]] = {}


def _add(rows: list[tuple[int, str, bool]]) -> None:
    for port, service, is_tls in rows:
        COMMON_PORTS[port] = (service, is_tls)


_add([
    (7, "echo", False), (19, "chargen", False), (20, "ftp-data", False), (21, "ftp", False),
    (22, "ssh", False), (23, "telnet", False), (25, "smtp", False), (37, "time", False),
    (43, "whois", False), (53, "dns", False), (67, "dhcp", False), (69, "tftp", False),
    (79, "finger", False), (80, "http", False), (88, "kerberos", False), (110, "pop3", False),
    (111, "rpcbind", False), (113, "ident", False), (119, "nntp", False), (123, "ntp", False),
    (135, "msrpc", False), (137, "netbios-ns", False), (138, "netbios-dgm", False),
    (139, "netbios-ssn", False), (143, "imap", False), (161, "snmp", False),
    (162, "snmptrap", False), (177, "xdmcp", False), (179, "bgp", False), (194, "irc", False),
    (199, "smux", False), (389, "ldap", False), (427, "svrloc", False), (443, "https", True),
    (444, "snpp", False), (445, "smb", False), (464, "kpasswd", False), (465, "smtps", True),
    (497, "retrospect", False), (500, "isakmp", False), (512, "exec", False),
    (513, "login", False), (514, "syslog", False), (515, "printer", False), (520, "rip", False),
    (523, "ibm-db2", False), (540, "uucp", False), (548, "afp", False), (554, "rtsp", False),
    (587, "smtp-submission", False), (591, "filemaker-http", False), (593, "http-rpc-epmap", False),
    (623, "ipmi", False), (631, "ipp", False), (636, "ldaps", True), (646, "ldp", False),
    (873, "rsync", False), (902, "vmware-auth", False), (989, "ftps-data", True),
    (990, "ftps", True), (993, "imaps", True), (995, "pop3s", True),
])

_add([
    (1025, "msrpc-alt", False), (1026, "msrpc-alt", False), (1027, "msrpc-alt", False),
    (1028, "msrpc-alt", False), (3268, "ldap-gc", False), (3269, "ldaps-gc", True),
    (3389, "rdp", False), (5722, "dfsr", False), (5985, "winrm-http", False),
    (5986, "winrm-https", True), (9389, "adws", False),
])

_add([
    (1433, "mssql", False), (1434, "mssql-browser", False), (1521, "oracle", False),
    (1830, "oracle-oms", False), (2181, "zookeeper", False), (2379, "etcd-client", False),
    (2380, "etcd-peer", False), (3050, "firebird", False), (3306, "mysql", False),
    (4333, "msql", False), (5342, "qpasa", False), (5432, "postgresql", False),
    (5433, "postgresql-alt", False), (5984, "couchdb", False), (6379, "redis", False),
    (6380, "redis-tls", True), (7000, "cassandra", False), (7199, "cassandra-jmx", False),
    (7473, "neo4j-https", True), (7474, "neo4j-http", False), (7687, "neo4j-bolt", False),
    (8086, "influxdb", False), (8087, "influxdb-alt", False), (8091, "couchbase-admin", False),
    (8529, "arangodb", False), (9042, "cassandra-cql", False), (9160, "cassandra-thrift", False),
    (9200, "elasticsearch", False), (9300, "elasticsearch-transport", False),
    (11211, "memcached", False), (15672, "rabbitmq-mgmt", False),
    (16379, "redis-cluster", False), (18080, "clickhouse-http", False),
    (27017, "mongodb", False), (27018, "mongodb-shard", False), (27019, "mongodb-config", False),
    (28015, "rethinkdb", False), (28017, "mongodb-http", False), (50000, "sap", False),
    (50070, "hadoop-namenode", False),
])

_add([
    (1883, "mqtt", False), (4369, "epmd-erlang", False), (5222, "xmpp-client", False),
    (5223, "xmpp-client-tls", True), (5269, "xmpp-server", False), (5671, "amqp-tls", True),
    (5672, "amqp", False), (8883, "mqtt-tls", True), (9092, "kafka", False),
    (61613, "stomp", False), (61616, "activemq", False),
])

_add([
    (2222, "ssh-alt", False), (2375, "docker", False), (2376, "docker-tls", True),
    (2377, "docker-swarm", False), (4243, "docker-alt", False), (4646, "nomad", False),
    (6443, "kubernetes-api", True), (8001, "kubernetes-dashboard", False),
    (8200, "vault", True), (8500, "consul", False), (8600, "consul-dns", False),
    (10250, "kubelet", True), (10255, "kubelet-readonly", False), (10256, "kube-proxy", False),
])

_add([
    (5601, "kibana", False), (8428, "victoriametrics", False), (9090, "prometheus", False),
    (9093, "alertmanager", False), (9100, "node-exporter", False),
    (10050, "zabbix-agent", False), (10051, "zabbix-server", False),
    (12900, "elastic-apm", False),
])

_add([
    (2082, "cpanel", False), (2083, "cpanel-ssl", True), (2086, "whm", False),
    (2087, "whm-ssl", True), (2095, "webmail", False), (2096, "webmail-ssl", True),
    (3000, "dev-http", False), (3001, "dev-http", False), (4000, "dev-http", False),
    (4200, "dev-http", False), (4443, "https-alt", True), (5000, "dev-http", False),
    (5001, "dev-http", False), (6000, "x11", False), (7070, "http-alt", False),
    (7777, "http-alt", False), (8000, "http-alt", False), (8008, "http-alt", False),
    (8009, "tomcat-ajp", False), (8080, "http-proxy", False), (8081, "http-alt", False),
    (8088, "http-alt", False), (8090, "http-alt", False), (8181, "http-alt", False),
    (8443, "https-alt", True), (8888, "http-alt", False), (8983, "solr", False),
    (9000, "php-fpm/dev", False), (9001, "http-alt", False), (9080, "http-alt", False),
    (9443, "https-alt", True), (9999, "http-alt", False),
])

_add([
    (3690, "svn", False), (8069, "odoo", False), (8140, "puppet", False),
    (9418, "git", False), (9990, "wildfly-mgmt", False), (10000, "webmin", False),
])

_add([
    (2049, "nfs", False), (2121, "ftp-alt", False), (5800, "vnc-http", False),
    (5900, "vnc", False), (5901, "vnc-alt", False), (6001, "x11-alt", False), (6667, "irc", False),
])

_add([
    (1099, "java-rmi", False), (4848, "glassfish-admin", True), (7001, "weblogic", False),
    (7002, "weblogic-tls", True), (8005, "tomcat-shutdown", False),
])

HIGH_RISK_PORTS = {
    23, 111, 137, 139, 161, 445, 512, 513, 514,
    1433, 1521, 2181, 2375, 2379, 3306, 3389, 5432, 5900, 5985,
    5984, 6379, 6380, 7199, 8200, 8500, 9042, 9090, 9200, 9300, 10250,
    11211, 27017, 27018, 27019,
}

HTTP_LIKE_PORTS = {
    80, 443, 591, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 3001, 4000,
    4200, 4443, 5000, 5001, 5601, 5984, 7001, 7070, 7474, 7777, 8000,
    8001, 8008, 8080, 8081, 8086, 8087, 8088, 8090, 8181, 8200, 8443,
    8500, 8888, 8983, 9000, 9001, 9080, 9090, 9200, 9443, 9999, 15672,
    18080, 28017,
}

_PORT_RE = re.compile(r"^\s*(\d{1,5})(?:\s*[-,]\s*(\d{1,5}))?\s*$")
_SSH_RE = re.compile(r"^SSH-\d+\.\d+-(?P<product>[^_\s]+)(?:_(?P<version>[^\s]+))?")
_SERVER_RE = re.compile(r"^server\s*:\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE)
_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(?P<status>\d{3})", re.MULTILINE)


@dataclass
class OpenPort:
    port: int
    service: str
    tls: bool = False
    banner: str = ""
    product: str = ""
    version: str = ""
    cert: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "port": self.port,
            "service": self.service,
            "tls": self.tls,
            "product": self.product,
            "version": self.version,
            "cert": self.cert,
        }


@dataclass
class PortScanResult:
    xml: str
    host: str
    address: str
    open_ports: list[OpenPort]
    stats: dict
    high_risk: list[OpenPort]


def _target_host(target: str) -> str:
    raw = (target or "").strip()
    if "://" in raw:
        from urllib.parse import urlsplit

        return (urlsplit(raw).hostname or "").strip().lower().rstrip(".")
    if raw.startswith("["):
        return raw[1:].split("]", 1)[0].strip().lower()
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    return raw.split("/", 1)[0].strip().lower().rstrip(".")


def _port_list(value) -> list[int]:
    if value in (None, "", []):
        return sorted(COMMON_PORTS)
    if isinstance(value, int):
        value = [value]
    if isinstance(value, str):
        value = [chunk for chunk in re.split(r"[,\s]+", value) if chunk]
    ports: list[int] = []
    for item in value:
        text = str(item).strip()
        if "-" in text:
            start, _, end = text.partition("-")
            try:
                low, high = int(start), int(end)
            except ValueError:
                continue
            if low > high:
                low, high = high, low
            for port in range(max(1, low), min(65535, high) + 1):
                if port not in ports:
                    ports.append(port)
                if len(ports) >= 1000:
                    break
            continue
        match = _PORT_RE.match(text)
        if not match:
            continue
        port = int(match.group(1))
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports[:1000]


def _banner_text(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    text = "".join(ch if ch in "\r\n\t" or ch.isprintable() else " " for ch in text)
    return text.strip()[:4096]


def _http_probe(sock: socket.socket, host: str) -> str:
    host_header = f"[{host}]" if ":" in host else host
    request = (
        f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\n"
        "User-Agent: Breadcrumb/0.1 (+local recon notebook)\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        sock.sendall(request.encode("ascii", errors="replace"))
        chunks: list[bytes] = []
        total = 0
        while total < 4096:
            chunk = sock.recv(min(4096 - total, 2048))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return _banner_text(b"".join(chunks))
    except (OSError, socket.timeout):
        return ""


def _parse_banner(banner: str) -> tuple[str, str]:
    """Best-effort product/version from an SSH or HTTP banner."""
    product = version = ""
    match = _SSH_RE.match(banner.strip())
    if match:
        product = match.group("product") or ""
        version = match.group("version") or ""
        if "/" in product:
            product, _, suffix = product.partition("/")
            version = version or suffix
        return product, version
    server = _SERVER_RE.search(banner or "")
    if server:
        value = server.group("value").strip()
        name, _, rest = value.partition("/")
        product = name.strip()
        version = rest.split(" ", 1)[0].strip()
    return product, version


def _certificate_fields(sock: ssl.SSLSocket) -> dict:
    """Extract a few useful certificate fields without trusting the peer."""
    try:
        der = sock.getpeercert(binary_form=True)
        if not der:
            return {}
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID

        cert = x509.load_der_x509_certificate(der)
        def _name(oid):
            attrs = cert.subject.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else ""

        san: list[str] = []
        try:
            extension = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san = list(extension.value.get_values_for_type(x509.DNSName))
        except Exception:  # noqa: BLE001  (missing SAN is normal)
            pass
        return {
            "subject_cn": str(_name(NameOID.COMMON_NAME)),
            "issuer_cn": str(
                cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                else ""
            ),
            "not_after": (
                getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            ).isoformat(),
            "san": san[:50],
        }
    except Exception:  # noqa: BLE001  (cert parsing is optional evidence)
        return {}


def _scan_one(
    ctx: CollectorContext,
    address: str,
    host: str,
    port: int,
    service: str,
    is_tls: bool,
    timeout: float,
    *,
    http_probe: bool = False,
) -> OpenPort | None:
    ctx.check_cancel()
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((address, port), timeout=timeout)
        sock.settimeout(min(2.0, timeout))
        cert: dict = {}
        if is_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                sock = context.wrap_socket(sock, server_hostname=host)
            except (ssl.SSLError, OSError):
                return None
            cert = _certificate_fields(sock)

        banner = ""
        try:
            sock.settimeout(0.8)
            banner = _banner_text(sock.recv(4096))
        except (socket.timeout, OSError):
            pass
        if not banner and (
            http_probe or service.startswith("http") or port in HTTP_LIKE_PORTS
        ):
            banner = _http_probe(sock, host)
        product, version = _parse_banner(banner)
        return OpenPort(
            port=port,
            service=service,
            tls=is_tls,
            banner=banner,
            product=product,
            version=version,
            cert=cert,
        )
    except (OSError, socket.timeout):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _xml_attr(value: object) -> str:
    return saxutils.quoteattr(str(value))[1:-1]


def _nmap_xml(host: str, address: str, opened: list[OpenPort], started: str) -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<nmaprun scanner="breadcrumb-native" args="connect scan {_xml_attr(host)}" start="{_xml_attr(started)}">',
        "<host>",
        '<status state="up" reason="connect"/>',
        f'<address addr="{_xml_attr(address)}" addrtype="{"ipv6" if ":" in address else "ipv4"}"/>',
        "<hostnames>",
        f'<hostname name="{_xml_attr(host)}" type="user"/>',
        "</hostnames>",
        "<ports>",
    ]
    for item in opened:
        service_attrs = [f'name="{_xml_attr(item.service)}"']
        if item.product:
            service_attrs.append(f'product="{_xml_attr(item.product)}"')
        if item.version:
            service_attrs.append(f'version="{_xml_attr(item.version)}"')
        if item.tls:
            service_attrs.append('tunnel="ssl"')
        lines.extend([
            f'<port protocol="tcp" portid="{item.port}">',
            '<state state="open" reason="syn-ack"/>',
            f'<service {" ".join(service_attrs)}/>',
        ])
        if item.banner:
            lines.append(
                f'<script id="banner" output="{_xml_attr(item.banner)}"/>'
            )
        if item.cert:
            lines.append(
                f'<script id="ssl-cert" output="{_xml_attr(json.dumps(item.cert, sort_keys=True))}"/>'
            )
        lines.append("</port>")
    lines.extend([
        "</ports>",
        "</host>",
        f'<runstats><finished time="{_xml_attr(started)}"/>'
        f'<hosts up="1" down="0" total="1"/></runstats>',
        "</nmaprun>",
    ])
    return "\n".join(lines) + "\n"


def scan_ports(
    ctx: CollectorContext,
    *,
    host: str | None = None,
    ports: list[int] | None = None,
    timeout: float = 3.0,
    concurrency: int = 10,
) -> PortScanResult:
    """Scan one host and return nmap XML plus structured open-port data.

    The caller must already have a scope decision for ``host`` (the standalone
    collector performs it; the recon orchestrator reuses the DNS decision).
    ``scan_ports`` repeats ``ctx.check_host`` once so the guard event and the
    pinned address are always recorded immediately before the connections.
    """
    if ctx.proxy:
        raise CollectorError(
            "native collectors do not support a proxy; clear the header "
            "profile proxy or use an external runner"
        )
    host = (host or _target_host(ctx.target)).strip().lower().rstrip(".")
    if not host:
        raise CollectorError("empty port-scan target")
    decision = ctx.check_host(host)
    if not decision.addresses:
        raise CollectorError("scope guard returned no pinned address")
    address = decision.addresses[0]
    selected = ports or _port_list(ctx.options.get("ports"))
    forced_http = set(_port_list(ctx.options.get("http_ports"))) if ctx.options.get("http_ports") else set()
    forced_tls = set(_port_list(ctx.options.get("tls_ports"))) if ctx.options.get("tls_ports") else set()
    if "://" in (ctx.target or ""):
        from urllib.parse import urlsplit

        parsed_target = urlsplit(ctx.target)
        if parsed_target.scheme.lower() == "https" and parsed_target.port:
            forced_tls.add(parsed_target.port)
    concurrency = max(1, min(int(concurrency or 10), 32))
    timeout = max(0.2, min(float(timeout), 15.0))

    ctx.emit_event(
        "phase",
        f"port scan {host} ({len(selected)} ports via {address})",
        host=host,
        address=address,
        ports=len(selected),
    )
    started = datetime.now(timezone.utc).isoformat()
    opened: list[OpenPort] = []
    errors = 0
    lock = threading.Lock()

    def probe(port: int) -> None:
        nonlocal errors
        service, mapped_tls = COMMON_PORTS.get(port, ("unknown", False))
        is_tls = mapped_tls or port in forced_tls
        try:
            result = _scan_one(
                ctx, address, host, port, service, is_tls, timeout,
                http_probe=port in forced_http,
            )
        except Exception:  # noqa: BLE001  (one port must not abort the scan)
            result = None
        with lock:
            if result is not None:
                opened.append(result)
            else:
                errors += 1

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(probe, port) for port in selected]
            for future in concurrent.futures.as_completed(futures):
                ctx.check_cancel()
                future.result()
    except Exception:
        # Cancellation must stop further work; re-raise after the pool closes.
        raise

    opened.sort(key=lambda item: item.port)
    high_risk = [item for item in opened if item.port in HIGH_RISK_PORTS]
    stats = {
        "host": host,
        "address": address,
        "ports_scanned": len(selected),
        "open": len(opened),
        "tls": sum(1 for item in opened if item.tls),
        "high_risk": len(high_risk),
        "closed_or_filtered": max(0, len(selected) - len(opened)),
        "errors": errors,
    }
    ctx.emit_event(
        "phase",
        f"port scan: {stats['open']} open, {stats['tls']} TLS, "
        f"{stats['high_risk']} high-risk",
        **stats,
    )
    return PortScanResult(
        xml=_nmap_xml(host, address, opened, started),
        host=host,
        address=address,
        open_ports=opened,
        stats=stats,
        high_risk=high_risk,
    )


def port_finding_records(result: PortScanResult) -> list[dict]:
    """Candidate findings for high-risk open services."""
    records: list[dict] = []
    for item in result.high_risk:
        label = item.product or item.service
        records.append(
            nuclei_record(
                template_id=f"native-open-{item.service}-port",
                name=f"High-risk service exposed: {label} on {item.port}/tcp",
                severity="medium",
                matched_at=f"{result.host}:{item.port}",
                description=(
                    f"Port {item.port}/tcp is open and commonly used by "
                    f"{item.service}. Exposure may be intentional; verify whether "
                    "the service requires authentication and network isolation."
                ),
                tags=["native", "candidate", "exposed-service"],
                matcher="open-port",
                extracted=[f"{item.port}/{item.service}", item.banner[:200]],
                host=result.host,
                port=item.port,
                extra={"service": item.service, "address": result.address},
            )
        )
    return records


@register
class PortScanCollector(Collector):
    id = "leadline-ports"
    label = "Native port scan"
    description = "TCP connect scan with banners and TLS certificate evidence."
    category = "native"

    def run(self, ctx: CollectorContext) -> CollectorResult:
        result = scan_ports(ctx)
        phases = [PhaseOutput("ports", result.xml, dict(result.stats))]
        records = port_finding_records(result)
        if records:
            phases.append(
                PhaseOutput(
                    "port-findings",
                    nuclei_jsonl(
                        records,
                        header="Native high-risk port candidates; manual verification required.",
                    ),
                    {"findings": len(records)},
                )
            )
        return CollectorResult(phases, dict(result.stats))
