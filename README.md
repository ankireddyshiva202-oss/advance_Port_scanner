# Advanced Port Scanner

An authorized TCP/UDP scanning and fingerprinting tool written in Python. It finds open ports, identifies likely services, grabs banners, fingerprints web technologies, inspects TLS certificates, and exports results to JSON or CSV.

Use this only on systems you own or have explicit permission to test.

## Why These Features

Mature scanners such as Nmap separate port state, service name, service/version evidence, and output formats. The scanner follows the same idea at a learning-project level: it does not only say "port open"; it also stores evidence such as banners, HTTP headers, TLS details, and confidence scores.

OWASP's Web Security Testing Guide treats fingerprinting as part of information gathering. This tool includes safe fingerprinting checks using HTTP headers, cookies, HTML markers, common framework paths, and security-header presence.

Python's `ssl` library exposes TLS certificate and cipher information through socket wrappers, so HTTPS-like services can be inspected without extra packages.

References:

- Nmap Reference Guide, output and version evidence: https://nmap.org/man/man-output.html
- Nmap XML output and service version fields: https://nmap.org/book/output-formats-xml-output.html
- OWASP Web Security Testing Guide, Information Gathering: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/
- Python `ssl` documentation: https://docs.python.org/3/library/ssl.html

## Features Added

- TCP scanning with configurable scan profiles.
- Basic UDP scanning for selected common UDP services.
- Domain, IP, CIDR, and simple IP range input.
- Target list file support.
- Concurrent scanning with configurable thread count.
- Timeout and delay controls.
- Banner grabbing with small service-specific probes.
- Service name lookup using the local OS service database.
- Basic product/version extraction from banners and server headers.
- HTTP probing for web ports.
- HTTP title extraction.
- HTTP method discovery through `OPTIONS`.
- HTTP security-header presence checks.
- Backend/framework/CMS fingerprinting.
- TLS version, cipher, issuer, subject, SAN, and expiry inspection.
- Confidence scores based on evidence quality.
- Progress display.
- JSON and CSV reporting.
- Verbose mode for extra HTTP/TLS details.

## Requirements

Python 3.9 or newer is recommended. The scanner uses only the Python standard library.

Check your Python version:

```bash
python --version
```

## Basic Usage

Quick scan of common TCP ports:

```bash
python advanced_port_scanner.py -t 127.0.0.1
```

Scan a domain:

```bash
python advanced_port_scanner.py -t example.com --scan web
```

Scan top 100 common TCP ports:

```bash
python advanced_port_scanner.py -t 192.168.1.10 --scan top-100
```

Scan all TCP ports:

```bash
python advanced_port_scanner.py -t 192.168.1.10 --scan full --threads 300 --timeout 1
```

Custom TCP ports:

```bash
python advanced_port_scanner.py -t 192.168.1.10 --scan custom --ports 22,80,443,8000-9000
```

Scan TCP plus common UDP ports:

```bash
python advanced_port_scanner.py -t 192.168.1.10 --udp
```

UDP-only scan:

```bash
python advanced_port_scanner.py -t 192.168.1.10 --udp-only --udp-ports 53,123,161
```

Save reports:

```bash
python advanced_port_scanner.py -t 192.168.1.10 --scan quick --json results.json --csv results.csv
```

## Target Input

Single host:

```bash
python advanced_port_scanner.py -t 192.168.1.10
```

Multiple hosts:

```bash
python advanced_port_scanner.py -t 192.168.1.10 192.168.1.20 example.com
```

CIDR range:

```bash
python advanced_port_scanner.py -t 192.168.1.0/24 --scan top-100
```

Simple last-octet range:

```bash
python advanced_port_scanner.py -t 192.168.1.1-20 --scan quick
```

Target file:

```bash
python advanced_port_scanner.py -f targets.txt --scan quick
```

Example `targets.txt`:

```text
192.168.1.10
192.168.1.20
example.com
192.168.1.0/30
```

## Scan Profiles

`quick`

Scans a curated set of common TCP ports. This is the default.

`top-100`

Scans a larger common TCP port list.

`web`

Scans common HTTP and HTTPS application ports.

`full`

Scans TCP ports `1-65535`. This can take time.

`custom`

Uses ports supplied with `--ports`.

## Important Options

`--threads`

Controls concurrency. Higher is faster but noisier.

```bash
python advanced_port_scanner.py -t 127.0.0.1 --threads 200
```

`--timeout`

Controls how long each socket waits.

```bash
python advanced_port_scanner.py -t 127.0.0.1 --timeout 2.5
```

`--delay`

Adds delay between submitted probes. Useful for gentler scans.

```bash
python advanced_port_scanner.py -t 127.0.0.1 --delay 0.05
```

`--no-http`

Disables HTTP fingerprinting.

```bash
python advanced_port_scanner.py -t example.com --scan web --no-http
```

`--verbose`

Prints extra HTTP methods, missing security headers, and fingerprint evidence.

```bash
python advanced_port_scanner.py -t example.com --scan web --verbose
```

## Output Fields

Each open service can include:

- `target`: original target name.
- `resolved_ip`: resolved IPv4 address.
- `protocol`: `tcp` or `udp`.
- `port`: port number.
- `state`: currently `open`.
- `service`: service name from the local service database.
- `banner`: text returned by the service.
- `product`: likely product parsed from banner/header evidence.
- `version`: likely version parsed from banner/header evidence.
- `confidence`: rough confidence score based on available evidence.
- `latency_ms`: connect or response time.
- `http`: HTTP status, title, server, cookies, methods, security headers, and technology guess.
- `tls`: TLS version, cipher, certificate subject, issuer, SANs, and expiry.

## Technology Detection

The scanner guesses backend language and frameworks from external evidence:

- HTTP `Server` header.
- HTTP `X-Powered-By` header.
- Cookies such as `PHPSESSID`, `csrftoken`, and `JSESSIONID`.
- HTML markers and asset paths such as `wp-content`, `__next`, React, Vue, Angular, Laravel, Django, and Rails markers.

This is fingerprinting, not proof. Reverse proxies, CDNs, disabled headers, custom deployments, and fake headers can hide or distort the real stack.

## Limitations

- It is not a replacement for Nmap.
- UDP scanning is limited because many UDP services do not respond unless the probe is perfect.
- OS detection is not implemented because reliable OS fingerprinting requires lower-level packet behavior that the Python standard library does not expose cleanly.
- Version detection is evidence-based and can be wrong.
- It does not exploit vulnerabilities or brute-force credentials.
- TLS verification is disabled during inspection so the scanner can still read self-signed lab certificates.

## Suggested Next Improvements

- Add IPv6 support.
- Add richer protocol parsers for SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, and Elasticsearch.
- Add HTML report generation.
- Add resume support for interrupted full scans.
- Add a plugin system for custom probes.
- Add passive CVE lookup from local offline data, not live exploitation.
- Add unit tests for parsing, target expansion, report writing, and fingerprinting.

## Safe Testing Lab

Good targets for learning:

- `127.0.0.1`
- your own router or VM lab
- Docker containers you start yourself
- intentionally vulnerable local labs such as DVWA or Metasploitable, only in an isolated environment

Avoid scanning public IP ranges, company networks, or university networks without written permission.
