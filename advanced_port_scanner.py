import argparse
import concurrent.futures
import csv
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 5000,
    5432, 5601, 5900, 5985, 5986, 6379, 8000, 8080, 8081, 8443, 9000, 9200,
    9300, 11211, 27017,
]

WEB_PORTS = [
    80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 3000, 5000,
]

DEFAULT_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900]

TOP_100_TCP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 445, 465, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

TECH_SIGNATURES = [
    ("wordpress", "PHP", "WordPress", "body/header marker"),
    ("wp-content", "PHP", "WordPress", "WordPress asset path"),
    ("wp-includes", "PHP", "WordPress", "WordPress asset path"),
    ("laravel", "PHP", "Laravel", "Laravel marker"),
    ("phpsessid", "PHP", None, "PHP session cookie"),
    ("x-powered-by: php", "PHP", None, "X-Powered-By header"),
    ("express", "Node.js", "Express.js", "Express marker"),
    ("x-powered-by: express", "Node.js", "Express.js", "X-Powered-By header"),
    ("node.js", "Node.js", None, "Node.js marker"),
    ("__next", "Node.js", "Next.js", "Next.js asset path"),
    ("next.js", "Node.js", "Next.js", "Next.js marker"),
    ("nuxt", "Node.js", "Nuxt", "Nuxt marker"),
    ("django", "Python", "Django", "Django marker"),
    ("csrftoken", "Python", "Django", "Django CSRF cookie"),
    ("flask", "Python", "Flask", "Flask marker"),
    ("werkzeug", "Python", "Werkzeug/Flask", "Werkzeug marker"),
    ("rails", "Ruby", "Ruby on Rails", "Rails marker"),
    ("_rails", "Ruby", "Ruby on Rails", "Rails marker"),
    ("asp.net", ".NET", "ASP.NET", "ASP.NET marker"),
    ("x-aspnet-version", ".NET", "ASP.NET", "ASP.NET header"),
    ("jsessionid", "Java", "Java Servlet", "JSESSIONID cookie"),
    ("spring", "Java", "Spring", "Spring marker"),
    ("react", None, "React", "React marker"),
    ("vue", None, "Vue.js", "Vue marker"),
    ("angular", None, "Angular", "Angular marker"),
    ("svelte", None, "Svelte", "Svelte marker"),
    ("drupal", "PHP", "Drupal", "Drupal marker"),
    ("joomla", "PHP", "Joomla", "Joomla marker"),
]


@dataclass
class HttpInfo:
    status_line: str = ""
    title: str = ""
    server: str = ""
    powered_by: str = ""
    cookies: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    security_headers: Dict[str, bool] = field(default_factory=dict)
    backend_language: str = "unknown"
    framework_or_cms: str = "unknown"
    evidence: List[str] = field(default_factory=list)


@dataclass
class TlsInfo:
    tls_version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    resolved_ip: str
    protocol: str
    port: int
    state: str
    service: str
    banner: str = ""
    product: str = "unknown"
    version: str = "unknown"
    confidence: int = 50
    latency_ms: Optional[float] = None
    http: Optional[HttpInfo] = None
    tls: Optional[TlsInfo] = None
    notes: List[str] = field(default_factory=list)


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title_parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data.strip())

    @property
    def title(self):
        return " ".join(part for part in self.title_parts if part)[:120]


def parse_ports(spec: str) -> List[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            if start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError(f"Invalid ports: {invalid}")
    return sorted(ports)


def targets_from_value(value: str) -> List[str]:
    value = value.strip()
    if not value:
        return []
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            return [str(ip) for ip in network.hosts()]
    except ValueError:
        pass
    range_match = re.fullmatch(r"(.+\.)?(\d{1,3})-(\d{1,3})", value)
    if range_match:
        prefix = range_match.group(1) or ""
        start = int(range_match.group(2))
        end = int(range_match.group(3))
        if start > end:
            raise ValueError(f"Invalid target range: {value}")
        return [f"{prefix}{i}" for i in range(start, end + 1)]
    return [value]


def load_targets(raw_targets: Optional[List[str]], path: Optional[str]) -> List[str]:
    targets = []
    if raw_targets:
        for target in raw_targets:
            targets.extend(targets_from_value(target))
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.extend(targets_from_value(line))
    return sorted(set(targets))


def resolve_target(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def service_name(port: int, protocol: str) -> str:
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


def tcp_probe_payload(port: int) -> bytes:
    probes = {
        21: b"\r\n",
        22: b"",
        25: b"EHLO scanner.local\r\n",
        80: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        110: b"\r\n",
        143: b"a001 CAPABILITY\r\n",
        443: b"",
        465: b"",
        587: b"EHLO scanner.local\r\n",
        6379: b"INFO\r\n",
        8080: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        9200: b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    }
    return probes.get(port, b"\r\n")


def udp_probe_payload(port: int) -> bytes:
    if port == 53:
        return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    if port == 123:
        return b"\x1b" + (47 * b"\0")
    if port == 161:
        return bytes.fromhex("302602010104067075626c6963a01902047fffffff020100020100300b300906052b060102010500")
    return b"\0"


def read_socket(sock: socket.socket, limit: int = 4096) -> bytes:
    chunks = []
    total = 0
    while total < limit:
        try:
            chunk = sock.recv(min(1024, limit - total))
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    return b"".join(chunks)


def grab_banner(target: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            payload = tcp_probe_payload(port)
            if payload:
                sock.sendall(payload)
            data = read_socket(sock)
        banner = data.decode(errors="ignore").strip()
        return " ".join(banner.split()) if banner else ""
    except OSError:
        return ""


def parse_product_version(service: str, banner: str) -> Tuple[str, str]:
    text = banner.strip()
    if not text:
        return "unknown", "unknown"
    patterns = [
        r"(OpenSSH)[_/ ]([\w.\-p]+)",
        r"(Apache)[/ ]([\w.\-]+)",
        r"(nginx)[/ ]([\w.\-]+)",
        r"(Microsoft-IIS)[/ ]([\w.\-]+)",
        r"(PostgreSQL)[/ ]([\w.\-]+)",
        r"(MySQL)[/ ]([\w.\-]+)",
        r"(Redis)[\s_/-]*server[\s_/-]*v?([\w.\-]+)",
        r"(vsFTPd)[ /]([\w.\-]+)",
        r"(ProFTPD)[ /]([\w.\-]+)",
        r"(Exim)[ /]([\w.\-]+)",
        r"(Postfix)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            product = match.group(1)
            version = match.group(2) if len(match.groups()) > 1 else "unknown"
            return product, version
    first_word = text.split(" ", 1)[0].strip()
    return first_word[:60] if first_word else service, "unknown"


def get_tls_info(target: str, port: int, timeout: float) -> Optional[TlsInfo]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                version = tls_sock.version() or ""
        san = [value for key, value in cert.get("subjectAltName", []) if key.lower() == "dns"]
        return TlsInfo(
            tls_version=version,
            cipher=cipher[0] if cipher else "",
            subject=parse_cert_name(cert.get("subject", [])),
            issuer=parse_cert_name(cert.get("issuer", [])),
            not_before=cert.get("notBefore", ""),
            not_after=cert.get("notAfter", ""),
            san=san,
        )
    except OSError:
        return None
    except ssl.SSLError:
        return None


def parse_cert_name(items: Sequence[Sequence[Tuple[str, str]]]) -> str:
    parts = []
    for row in items:
        for key, value in row:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def http_request(target: str, port: int, timeout: float, method: str = "GET") -> str:
    use_tls = port in {443, 8443}
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)
    sock = raw_sock
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=target)
        sock.connect((target, port))
        request = (
            f"{method} / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: AdvancedPortScanner/2.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode())
        data = read_socket(sock, 20000)
        return data.decode(errors="ignore")
    finally:
        sock.close()


def parse_http_response(response: str) -> Tuple[str, Dict[str, List[str]], str]:
    if "\r\n\r\n" in response:
        raw_headers, body = response.split("\r\n\r\n", 1)
    else:
        raw_headers, body = response, ""
    lines = raw_headers.splitlines()
    status_line = lines[0] if lines else ""
    headers: Dict[str, List[str]] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers.setdefault(key.strip().lower(), []).append(value.strip())
    return status_line, headers, body


def get_http_info(target: str, port: int, timeout: float) -> Optional[HttpInfo]:
    try:
        response = http_request(target, port, timeout, "GET")
        status_line, headers, body = parse_http_response(response)
        if not status_line.startswith("HTTP/"):
            return None
        methods = []
        try:
            options_response = http_request(target, port, timeout, "OPTIONS")
            _, option_headers, _ = parse_http_response(options_response)
            allow = ",".join(option_headers.get("allow", []))
            methods = sorted({method.strip() for method in allow.split(",") if method.strip()})
        except OSError:
            methods = []
        title_parser = TitleParser()
        title_parser.feed(body[:10000])
        combined_text = build_fingerprint_text(headers, body)
        language, framework, evidence = detect_technology(combined_text)
        return HttpInfo(
            status_line=status_line,
            title=title_parser.title,
            server=", ".join(headers.get("server", [])),
            powered_by=", ".join(headers.get("x-powered-by", [])),
            cookies=headers.get("set-cookie", []),
            methods=methods,
            security_headers={header: header in headers for header in SECURITY_HEADERS},
            backend_language=language,
            framework_or_cms=framework,
            evidence=evidence,
        )
    except OSError:
        return None
    except ssl.SSLError:
        return None


def build_fingerprint_text(headers: Dict[str, List[str]], body: str) -> str:
    header_text = []
    for key, values in headers.items():
        for value in values:
            header_text.append(f"{key}: {value}")
    return ("\n".join(header_text) + "\n" + body[:20000]).lower()


def detect_technology(text: str) -> Tuple[str, str, List[str]]:
    language = "unknown"
    framework = "unknown"
    evidence = []
    for marker, marker_language, marker_framework, marker_evidence in TECH_SIGNATURES:
        if marker in text:
            if language == "unknown" and marker_language:
                language = marker_language
            if framework == "unknown" and marker_framework:
                framework = marker_framework
            if marker_evidence not in evidence:
                evidence.append(marker_evidence)
    return language, framework, evidence


def scan_tcp(target: str, resolved_ip: str, port: int, timeout: float, http_fingerprint: bool) -> Optional[ScanResult]:
    started = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((resolved_ip, port))
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
        if result != 0:
            return None
    except OSError:
        return None

    service = service_name(port, "tcp")
    banner = grab_banner(resolved_ip, port, timeout)
    product, version = parse_product_version(service, banner)
    scan_result = ScanResult(
        target=target,
        resolved_ip=resolved_ip,
        protocol="tcp",
        port=port,
        state="open",
        service=service,
        banner=banner,
        product=product,
        version=version,
        confidence=80 if banner else 60,
        latency_ms=latency_ms,
    )

    if port in {443, 8443, 465, 587, 993, 995}:
        tls_info = get_tls_info(target, port, timeout)
        if tls_info:
            scan_result.tls = tls_info
            scan_result.confidence = max(scan_result.confidence, 90)

    if http_fingerprint and (port in WEB_PORTS or service in {"http", "https", "http-alt"}):
        http_info = get_http_info(target, port, timeout)
        if http_info:
            scan_result.http = http_info
            scan_result.confidence = max(scan_result.confidence, 90)
            if http_info.server and scan_result.product == "unknown":
                scan_result.product, scan_result.version = parse_product_version(service, http_info.server)

    return scan_result


def scan_udp(target: str, resolved_ip: str, port: int, timeout: float) -> Optional[ScanResult]:
    started = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(udp_probe_payload(port), (resolved_ip, port))
            data, _ = sock.recvfrom(4096)
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
    except socket.timeout:
        return None
    except OSError:
        return None

    banner = data.decode(errors="ignore").strip()
    return ScanResult(
        target=target,
        resolved_ip=resolved_ip,
        protocol="udp",
        port=port,
        state="open",
        service=service_name(port, "udp"),
        banner=" ".join(banner.split()) if banner else "UDP response received",
        confidence=70,
        latency_ms=latency_ms,
    )


def flatten_result(result: ScanResult) -> Dict[str, object]:
    data = asdict(result)
    if result.http:
        data["http"] = asdict(result.http)
    if result.tls:
        data["tls"] = asdict(result.tls)
    return data


def print_result(result: ScanResult, verbose: bool = False) -> None:
    head = (
        f"[OPEN] {result.target} ({result.resolved_ip}) "
        f"{result.port}/{result.protocol} {result.service} "
        f"confidence={result.confidence}%"
    )
    print(head)
    details = []
    if result.product != "unknown":
        details.append(f"product={result.product}")
    if result.version != "unknown":
        details.append(f"version={result.version}")
    if result.latency_ms is not None:
        details.append(f"latency={result.latency_ms}ms")
    if details:
        print("  " + " | ".join(details))
    if result.banner:
        print(f"  banner: {result.banner[:220]}")
    if result.http:
        print(f"  http: {result.http.status_line} title={result.http.title or 'unknown'}")
        print(f"  web tech: backend={result.http.backend_language} framework={result.http.framework_or_cms}")
        if result.http.server:
            print(f"  server: {result.http.server}")
        if result.http.powered_by:
            print(f"  powered-by: {result.http.powered_by}")
        if verbose:
            missing = [key for key, present in result.http.security_headers.items() if not present]
            print(f"  methods: {', '.join(result.http.methods) if result.http.methods else 'unknown'}")
            print(f"  missing security headers: {', '.join(missing) if missing else 'none'}")
            if result.http.evidence:
                print(f"  evidence: {', '.join(result.http.evidence)}")
    if result.tls:
        print(f"  tls: {result.tls.tls_version} cipher={result.tls.cipher}")
        print(f"  cert: subject={result.tls.subject or 'unknown'}")
        print(f"  cert: issuer={result.tls.issuer or 'unknown'} expires={result.tls.not_after or 'unknown'}")


def save_json(results: List[ScanResult], path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump([flatten_result(result) for result in results], handle, indent=2)


def save_csv(results: List[ScanResult], path: str) -> None:
    fields = [
        "target", "resolved_ip", "protocol", "port", "state", "service",
        "product", "version", "confidence", "latency_ms", "banner",
        "http_status", "http_title", "backend_language", "framework_or_cms",
        "server", "powered_by", "tls_version", "tls_cipher", "cert_expiry",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            row = {
                "target": result.target,
                "resolved_ip": result.resolved_ip,
                "protocol": result.protocol,
                "port": result.port,
                "state": result.state,
                "service": result.service,
                "product": result.product,
                "version": result.version,
                "confidence": result.confidence,
                "latency_ms": result.latency_ms,
                "banner": result.banner,
                "http_status": result.http.status_line if result.http else "",
                "http_title": result.http.title if result.http else "",
                "backend_language": result.http.backend_language if result.http else "",
                "framework_or_cms": result.http.framework_or_cms if result.http else "",
                "server": result.http.server if result.http else "",
                "powered_by": result.http.powered_by if result.http else "",
                "tls_version": result.tls.tls_version if result.tls else "",
                "tls_cipher": result.tls.cipher if result.tls else "",
                "cert_expiry": result.tls.not_after if result.tls else "",
            }
            writer.writerow(row)


def build_port_list(args: argparse.Namespace) -> Tuple[List[int], List[int]]:
    if args.scan == "custom":
        tcp_ports = parse_ports(args.ports or "")
    elif args.scan == "full":
        tcp_ports = list(range(1, 65536))
    elif args.scan == "top-100":
        tcp_ports = TOP_100_TCP_PORTS
    elif args.scan == "web":
        tcp_ports = WEB_PORTS
    else:
        tcp_ports = DEFAULT_TCP_PORTS
    udp_ports = parse_ports(args.udp_ports) if args.udp_ports else DEFAULT_UDP_PORTS
    return sorted(set(tcp_ports)), sorted(set(udp_ports))


def run_scan(args: argparse.Namespace) -> List[ScanResult]:
    targets = load_targets(args.target, args.file)
    if not targets:
        raise ValueError("Provide at least one target with --target or --file.")

    tcp_ports, udp_ports = build_port_list(args)
    if args.udp_only:
        tcp_ports = []
    if not args.udp and not args.udp_only:
        udp_ports = []

    resolved = []
    for target in targets:
        ip = resolve_target(target)
        if ip:
            resolved.append((target, ip))
        else:
            print(f"[WARN] Could not resolve target: {target}")

    results: List[ScanResult] = []
    started_at = datetime.now(timezone.utc).isoformat()
    print(f"Started: {started_at}")
    print(f"Targets: {len(resolved)} | TCP ports: {len(tcp_ports)} | UDP ports: {len(udp_ports)}")

    work = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        for target, ip in resolved:
            for port in tcp_ports:
                work.append(executor.submit(scan_tcp, target, ip, port, args.timeout, not args.no_http))
                if args.delay:
                    time.sleep(args.delay)
            for port in udp_ports:
                work.append(executor.submit(scan_udp, target, ip, port, args.timeout))
                if args.delay:
                    time.sleep(args.delay)

        total = len(work)
        completed = 0
        for future in concurrent.futures.as_completed(work):
            completed += 1
            if args.progress and total:
                print(f"\rProgress: {completed}/{total}", end="")
            result = future.result()
            if result:
                results.append(result)
                if args.progress:
                    print()
                print_result(result, args.verbose)
    if args.progress:
        print()
    return sorted(results, key=lambda item: (item.target, item.protocol, item.port))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authorized TCP/UDP port scanner with banners, HTTP fingerprinting, and TLS inspection."
    )
    parser.add_argument("-t", "--target", nargs="*", help="Target host, IP, CIDR, or last-octet range.")
    parser.add_argument("-f", "--file", help="File containing one target per line.")
    parser.add_argument("-p", "--ports", help="Custom TCP ports, for example 22,80,443 or 1-1024.")
    parser.add_argument("--udp-ports", help="Custom UDP ports, for example 53,123,161.")
    parser.add_argument(
        "--scan",
        choices=["quick", "top-100", "web", "full", "custom"],
        default="quick",
        help="TCP scan profile. Use custom with --ports.",
    )
    parser.add_argument("--udp", action="store_true", help="Also scan selected UDP ports.")
    parser.add_argument("--udp-only", action="store_true", help="Scan UDP only.")
    parser.add_argument("--threads", type=int, default=100, help="Maximum worker threads.")
    parser.add_argument("--timeout", type=float, default=1.5, help="Socket timeout in seconds.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between submitted probes.")
    parser.add_argument("--no-http", action="store_true", help="Disable HTTP fingerprint requests.")
    parser.add_argument("--progress", action="store_true", help="Show task progress.")
    parser.add_argument("--verbose", action="store_true", help="Print more HTTP/TLS details.")
    parser.add_argument("--json", help="Write JSON report.")
    parser.add_argument("--csv", help="Write CSV report.")
    args = parser.parse_args()
    if args.scan == "custom" and not args.ports:
        parser.error("--scan custom requires --ports")
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    return args


def main() -> None:
    args = parse_args()
    started = time.perf_counter()
    results = run_scan(args)
    duration = round(time.perf_counter() - started, 2)
    if args.json:
        save_json(results, args.json)
        print(f"Saved JSON report: {args.json}")
    if args.csv:
        save_csv(results, args.csv)
        print(f"Saved CSV report: {args.csv}")
    print(f"Finished. Open services found: {len(results)}. Duration: {duration}s")


if __name__ == "__main__":
    main()
