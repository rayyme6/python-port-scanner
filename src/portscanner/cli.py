#!/usr/bin/env python3
"""
portscanner.cli — TCP port scanner with HTTP, TLS, and banner identification.

Scan engines:
  * connect — multithreaded full TCP connections over IPv4 or IPv6 using
              Python sockets. No special privileges required.
  * syn     — rate-controlled, batched half-open IPv4/IPv6 SYN scanning using
              Scapy. Requires raw-socket privileges (normally sudo on Linux).

Only scan systems and networks you own or are explicitly authorized to test.

Examples:
    portscan 192.168.1.10 -p 1-1024
    portscan ::1 -p 22,80,443
    portscan example.com -6 -p 22,80,443 --show-all
    portscan example.com --profile reliable --timeout 2
    portscan example.com -p 443,8443 --banner-threads 5
    sudo .venv/bin/portscan 192.168.1.10 --syn --profile reliable
"""

import argparse
import csv
import errno
import io
import hashlib
import ipaddress
import json
import os
import random
import socket
import ssl
import sys
from contextlib import redirect_stderr
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from . import __version__

IP = IPv6 = TCP = ICMP = None
conf = send = sr = None
ICMPV6_ERROR_LAYERS = ()
SCAPY_AVAILABLE = False
SCAPY_IMPORT_ATTEMPTED = False
SCAPY_IMPORT_ERROR = None
SCAPY_IMPORT_DIAGNOSTICS = ""


def load_scapy():
    """Load Scapy lazily so connect scans do not initialize raw networking."""
    global IP, IPv6, TCP, ICMP, conf, send, sr
    global ICMPV6_ERROR_LAYERS, SCAPY_AVAILABLE
    global SCAPY_IMPORT_ATTEMPTED, SCAPY_IMPORT_ERROR
    global SCAPY_IMPORT_DIAGNOSTICS

    if SCAPY_IMPORT_ATTEMPTED:
        return SCAPY_AVAILABLE

    SCAPY_IMPORT_ATTEMPTED = True
    diagnostics = io.StringIO()
    try:
        # Scapy performs route discovery while importing IPv6 support. Capture
        # its diagnostics and report a concise error only when SYN mode is used.
        with redirect_stderr(diagnostics):
            from scapy.all import (  # type: ignore[import-not-found]
                ICMP as scapy_icmp,
                IP as scapy_ip,
                IPv6 as scapy_ipv6,
                TCP as scapy_tcp,
                conf as scapy_conf,
                send as scapy_send,
                sr as scapy_sr,
            )
            from scapy.layers.inet6 import (  # type: ignore[import-not-found]
                ICMPv6DestUnreach,
                ICMPv6PacketTooBig,
                ICMPv6ParamProblem,
                ICMPv6TimeExceeded,
            )

        IP = scapy_ip
        IPv6 = scapy_ipv6
        TCP = scapy_tcp
        ICMP = scapy_icmp
        conf = scapy_conf
        send = scapy_send
        sr = scapy_sr
        ICMPV6_ERROR_LAYERS = (
            ICMPv6DestUnreach,
            ICMPv6PacketTooBig,
            ICMPv6TimeExceeded,
            ICMPv6ParamProblem,
        )
        SCAPY_AVAILABLE = True
        SCAPY_IMPORT_ERROR = None
    except Exception as exc:  # Scapy can fail while initializing route tables.
        SCAPY_AVAILABLE = False
        SCAPY_IMPORT_ERROR = exc
    finally:
        SCAPY_IMPORT_DIAGNOSTICS = diagnostics.getvalue()

    return SCAPY_AVAILABLE


SCANNER_NAME = "python-port-scanner"
SCANNER_VERSION = __version__
REPORT_FORMATS = ("auto", "text", "json", "csv")
DEFAULT_MAX_TARGETS = 256
DEFAULT_MAX_PROBES = 1_000_000

DEFAULT_PROFILE = "balanced"
PROFILE_SETTING_NAMES = ("timeout", "threads", "batch_size", "inter", "retries")
SCAN_PROFILES = {
    "fast": {
        "timeout": 0.5,
        "threads": 200,
        "batch_size": 1024,
        "inter": 0.0,
        "retries": 0,
    },
    "balanced": {
        "timeout": 1.0,
        "threads": 100,
        "batch_size": 512,
        "inter": 0.001,
        "retries": 1,
    },
    "reliable": {
        "timeout": 1.5,
        "threads": 50,
        "batch_size": 256,
        "inter": 0.003,
        "retries": 2,
    },
}


class ScanInterrupted(KeyboardInterrupt):
    """Carry safely collected results when a user interrupts a scan stage."""

    def __init__(
        self,
        results=None,
        stage="scan",
        stage_completed=None,
        stage_total=None,
    ):
        super().__init__()
        self.results = sorted(
            list(results or []),
            key=lambda result: int(result.get("port", 0)),
        )
        self.stage = str(stage)
        self.stage_completed = int(
            len(self.results) if stage_completed is None else stage_completed
        )
        self.stage_total = int(
            self.stage_completed if stage_total is None else stage_total
        )


# Conventional service labels. These are fallbacks, not definitive proof of
# which application is actually listening on a port.
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    111: "RPCbind", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    631: "IPP", 636: "LDAPS", 853: "DNS-over-TLS", 989: "FTPS-DATA",
    990: "FTPS", 992: "TelnetS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2375: "Docker", 2376: "Docker-TLS",
    3000: "Dev-HTTP",
    3306: "MySQL", 3389: "RDP", 5000: "Dev-HTTP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 9443: "HTTPS-Alt",
    10443: "HTTPS-Alt", 27017: "MongoDB",
}

# Plain HTTP probes are useful on likely web ports and unknown ports. They are
# intentionally not sent to known non-HTTP protocols such as DNS or Telnet.
HTTP_PROBE_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9200}

# Ports that conventionally start with TLS immediately after the TCP handshake.
TLS_PROBE_PORTS = {
    443, 465, 636, 853, 989, 990, 992, 993, 995, 2376, 8443, 9443, 10443
}

# TLS ports where an encrypted HTTP request is appropriate.
HTTPS_PROBE_PORTS = {443, 8443, 9443, 10443}

# Errors that clearly indicate pressure or exhaustion on the scanner itself.
# EAGAIN/EWOULDBLOCK are deliberately handled separately: in timeout mode they
# can surface for a connection that never completed, so reporting them as a
# definite local resource failure would be misleading.
TRANSIENT_LOCAL_ERRORS = {
    value
    for value in (
        getattr(errno, "ENOBUFS", None),
        getattr(errno, "ENOMEM", None),
        getattr(errno, "EMFILE", None),
        getattr(errno, "ENFILE", None),
        getattr(errno, "EADDRNOTAVAIL", None),
    )
    if value is not None
}

AMBIGUOUS_CONNECT_ERRORS = {
    value
    for value in (
        getattr(errno, "EAGAIN", None),
        getattr(errno, "EWOULDBLOCK", None),
        getattr(errno, "EINPROGRESS", None),
        getattr(errno, "EALREADY", None),
    )
    if value is not None
}


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------


def parse_ports(port_spec):
    """Parse values such as '22,80,443', '1-1024', or a mixture."""
    ports = set()

    for raw_part in port_spec.split(","):
        part = raw_part.strip()
        if not part:
            continue

        try:
            if "-" in part:
                if part.count("-") != 1:
                    raise ValueError
                start_text, end_text = part.split("-", 1)
                start = int(start_text)
                end = int(end_text)

                if not 1 <= start <= end <= 65535:
                    raise ValueError

                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError
                ports.add(port)
        except ValueError:
            raise ValueError("invalid port or range: '{}'".format(part))

    if not ports:
        raise ValueError("no ports specified")

    return sorted(ports)


def strip_address_brackets(value):
    """Remove URI-style brackets from an IPv6 literal."""
    value = str(value).strip()
    if value.startswith("[") and value.endswith("]"):
        return value[1:-1]
    return value


def address_family(address):
    """Return socket.AF_INET or socket.AF_INET6 for an IP literal."""
    parsed = ipaddress.ip_address(strip_address_brackets(address))
    return socket.AF_INET6 if parsed.version == 6 else socket.AF_INET


def address_family_name(address_or_family):
    """Return a stable human-readable address-family label."""
    family = (
        address_or_family
        if isinstance(address_or_family, int)
        else address_family(address_or_family)
    )
    if family == socket.AF_INET6:
        return "IPv6"
    if family == socket.AF_INET:
        return "IPv4"
    return "unknown"


def socket_endpoint(address, port):
    """Build the correct connect() endpoint for IPv4 or IPv6."""
    address = strip_address_brackets(address)
    if address_family(address) == socket.AF_INET:
        return address, int(port)

    host = address
    scope_id = 0
    if "%" in address:
        host, scope = address.rsplit("%", 1)
        try:
            scope_id = int(scope)
        except ValueError:
            try:
                scope_id = socket.if_nametoindex(scope)
            except (AttributeError, OSError):
                raise ValueError("unknown IPv6 scope interface '{}'".format(scope))
    return host, int(port), 0, scope_id


def resolve_target(target, family="auto"):
    """Resolve a hostname or IP literal to one IPv4 or IPv6 address.

    ``auto`` preserves the scanner's historical IPv4 preference when both
    families are available, while still accepting IPv6 literals and falling
    back to IPv6-only DNS results. ``ipv4`` and ``ipv6`` force one family.
    """
    if family not in {"auto", "ipv4", "ipv6"}:
        raise ValueError("unknown address family: {}".format(family))

    candidate = strip_address_brackets(target)
    try:
        literal = ipaddress.ip_address(candidate)
    except ValueError:
        literal = None

    if literal is not None:
        literal_family = "ipv6" if literal.version == 6 else "ipv4"
        if family != "auto" and family != literal_family:
            raise ValueError(
                "target '{}' is {}, but --{} was requested".format(
                    target, literal_family.upper(), "6" if family == "ipv6" else "4"
                )
            )
        return str(literal)

    requested_family = {
        "auto": socket.AF_UNSPEC,
        "ipv4": socket.AF_INET,
        "ipv6": socket.AF_INET6,
    }[family]

    try:
        records = socket.getaddrinfo(
            candidate,
            None,
            requested_family,
            socket.SOCK_STREAM,
        )
    except socket.gaierror:
        raise ValueError("could not resolve host '{}'".format(target))

    addresses = []
    for record_family, _socktype, _protocol, _canonname, sockaddr in records:
        if record_family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = sockaddr[0]
        item = (record_family, address)
        if item not in addresses:
            addresses.append(item)

    if not addresses:
        raise ValueError("could not resolve host '{}'".format(target))

    if family == "auto":
        addresses.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
    return addresses[0][1]


def chunked(values, size):
    """Yield slices of values with at most size entries each."""
    for start in range(0, len(values), size):
        yield values[start:start + size]


def read_target_file(path):
    """Read target specifications from a UTF-8 text file.

    Blank lines and lines beginning with ``#`` are ignored. Inline comments are
    supported after whitespace, so ``192.0.2.1  # router`` is valid.
    """
    specifications = []
    try:
        with open(path, "r", encoding="utf-8") as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if " #" in line:
                    line = line.split(" #", 1)[0].rstrip()
                if not line:
                    continue
                specifications.append(line)
    except OSError as exc:
        raise ValueError("could not read target file '{}': {}".format(path, exc))
    return specifications


def network_host_count(network):
    """Return the number of addresses yielded by ``network.hosts()``."""
    if network.version == 4:
        if network.prefixlen >= 31:
            return int(network.num_addresses)
        return max(0, int(network.num_addresses) - 2)
    if network.prefixlen >= 127:
        return int(network.num_addresses)
    return max(0, int(network.num_addresses) - 1)


def parse_network_spec(specification):
    """Return an ip_network object for a CIDR specification, or ``None``."""
    specification = str(specification).strip()
    if "/" not in specification:
        return None

    # Accept URI-style bracketed IPv6 CIDRs such as ``[2001:db8::]/126``.
    if specification.startswith("[") and "]" in specification:
        closing = specification.index("]")
        specification = specification[1:closing] + specification[closing + 1:]
    try:
        return ipaddress.ip_network(specification, strict=False)
    except ValueError:
        return None


def collect_targets(
    positional_targets,
    target_files=None,
    family="auto",
    max_targets=DEFAULT_MAX_TARGETS,
):
    """Expand direct targets, target files, and CIDR ranges safely.

    Targets are deduplicated by resolved address while preserving first-seen
    order. CIDR ranges use ``ipaddress.ip_network(...).hosts()`` so ordinary
    IPv4 network and broadcast addresses are not scanned.
    """
    max_targets = int(max_targets)
    if max_targets <= 0:
        raise ValueError("max targets must be greater than zero")

    specifications = [str(value).strip() for value in positional_targets or []]
    for file_path in target_files or []:
        specifications.extend(read_target_file(file_path))
    specifications = [value for value in specifications if value]
    if not specifications:
        raise ValueError("provide at least one TARGET or --targets-file FILE")

    targets = []
    seen = set()

    def add_target(input_value, resolved_ip, expanded_from=None):
        key = (address_family(resolved_ip), resolved_ip)
        if key in seen:
            return
        if len(targets) >= max_targets:
            raise ValueError(
                "target expansion exceeds --max-targets {} (increase the limit "
                "only for an authorized scan)".format(max_targets)
            )
        seen.add(key)
        targets.append({
            "input": str(input_value),
            "resolved_ip": str(resolved_ip),
            "address_family": address_family_name(resolved_ip),
            "expanded_from": expanded_from,
        })

    for specification in specifications:
        network = parse_network_spec(specification)
        if "/" in specification and network is None:
            raise ValueError("invalid CIDR target: '{}'".format(specification))
        if network is not None:
            network_family = "ipv6" if network.version == 6 else "ipv4"
            if family != "auto" and family != network_family:
                raise ValueError(
                    "target '{}' is {}, but --{} was requested".format(
                        specification,
                        network_family.upper(),
                        "6" if family == "ipv6" else "4",
                    )
                )
            remaining = max_targets - len(targets)
            count = network_host_count(network)
            overlapping = 0
            for _seen_family, seen_address in seen:
                try:
                    if ipaddress.ip_address(seen_address) in network:
                        overlapping += 1
                except ValueError:
                    continue
            new_count = max(0, count - overlapping)
            if new_count > remaining:
                raise ValueError(
                    "CIDR '{}' expands to {} host(s) ({} new), exceeding the "
                    "remaining --max-targets capacity of {}".format(
                        specification, count, new_count, remaining
                    )
                )
            for host in network.hosts():
                add_target(str(host), str(host), expanded_from=specification)
            continue

        if family == "auto":
            # Preserve compatibility with one-argument resolvers and callers.
            resolved = resolve_target(specification)
        else:
            resolved = resolve_target(specification, family=family)
        add_target(specification, resolved)

    if not targets:
        raise ValueError("no usable targets were produced")
    return targets


def validate_probe_plan(target_count, port_count, max_probes=DEFAULT_MAX_PROBES):
    """Validate and return the planned target/port probe count."""
    max_probes = int(max_probes)
    if max_probes <= 0:
        raise ValueError("max probes must be greater than zero")
    planned = int(target_count) * int(port_count)
    if planned > max_probes:
        raise ValueError(
            "scan would schedule {:,} target-port probe(s), exceeding "
            "--max-probes {:,}; narrow the targets/ports or explicitly raise "
            "the limit for an authorized scan".format(planned, max_probes)
        )
    return planned


# ---------------------------------------------------------------------------
# Service and banner identification
# ---------------------------------------------------------------------------


def strip_telnet_negotiation(data):
    """Remove common Telnet IAC negotiation sequences from raw bytes."""
    output = bytearray()
    index = 0

    while index < len(data):
        byte = data[index]

        if byte != 0xFF:  # IAC
            output.append(byte)
            index += 1
            continue

        if index + 1 >= len(data):
            break

        command = data[index + 1]

        if command == 0xFF:  # Escaped literal 0xFF
            output.append(0xFF)
            index += 2
        elif command in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT + option
            index += 3
        elif command == 0xFA:  # SB ... IAC SE
            end = data.find(b"\xff\xf0", index + 2)
            index = len(data) if end == -1 else end + 2
        else:
            index += 2

    return bytes(output)


def readable_banner(data, port):
    """Convert a raw service response into one safe, readable terminal line."""
    if not data:
        return ""

    cleaned = strip_telnet_negotiation(data) if port == 23 else data
    text = cleaned.decode("utf-8", errors="replace").replace("\x00", " ")

    # Replace remaining control/binary characters while preserving line breaks.
    safe_chars = []
    for char in text:
        if char in "\r\n\t" or char.isprintable():
            safe_chars.append(char)
        else:
            safe_chars.append(" ")

    for line in "".join(safe_chars).splitlines():
        compact = " ".join(line.split())
        if compact:
            return compact[:160]

    if port == 23:
        return "Telnet negotiation received"
    return "binary response ({} bytes)".format(len(data))


def is_ip_literal(value):
    """Return True when value is an IPv4 or IPv6 literal rather than a hostname."""
    try:
        ipaddress.ip_address(strip_address_brackets(value))
        return True
    except ValueError:
        return False


def http_host_header(target, port, secure=False):
    """Build a hostname-aware HTTP Host header, including IPv6 brackets."""
    default_port = 443 if secure else 80
    host = strip_address_brackets(target)
    if is_ip_literal(host) and address_family(host) == socket.AF_INET6:
        host = "[{}]".format(host)
    return host if port == default_port else "{}:{}".format(host, port)


def build_http_request(target, port, secure=False, method="HEAD"):
    """Create a small hostname-aware HTTP request."""
    method = method.upper()
    if method not in {"HEAD", "GET"}:
        raise ValueError("unsupported HTTP probe method: {}".format(method))
    return (
        "{} / HTTP/1.0\r\n"
        "Host: {}\r\n"
        "User-Agent: {}/{}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).format(
        method,
        http_host_header(target, port, secure=secure),
        SCANNER_NAME,
        SCANNER_VERSION,
    ).encode()


def receive_response(sock, max_bytes=16384):
    """Read enough of a response to capture its status line and headers."""
    chunks = []
    total = 0

    while total < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - total))
        except (socket.timeout, ssl.SSLError):
            break

        if not chunk:
            break

        chunks.append(chunk)
        total += len(chunk)
        combined = b"".join(chunks)
        if b"\r\n\r\n" in combined or b"\n\n" in combined:
            break

    return b"".join(chunks)


def http_response_banner(data):
    """Extract a compact server identifier or status line from an HTTP response."""
    if not data[:16].upper().startswith(b"HTTP/"):
        return ""

    text = data.decode("iso-8859-1", errors="replace")
    lines = text.splitlines()
    server_line = next(
        (line for line in lines if line.lower().startswith("server:")),
        None,
    )
    if server_line:
        return server_line.split(":", 1)[1].strip()
    if lines:
        return " ".join(lines[0].split())
    return "HTTP response"


def certificate_name_value(name, key_name):
    """Read one value such as commonName from ssl's decoded certificate tuples."""
    for relative_name in name or ():
        for key, value in relative_name:
            if key == key_name:
                return str(value)
    return ""


def normalize_dns_name(value):
    """Normalize a DNS name to lowercase IDNA ASCII without a trailing dot."""
    value = value.rstrip(".")
    try:
        return value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return value.lower()


def dns_pattern_matches(pattern, hostname):
    """Match an exact DNS name or a single-label leading wildcard."""
    pattern = normalize_dns_name(pattern)
    hostname = normalize_dns_name(hostname)

    if "*" not in pattern:
        return pattern == hostname

    pattern_labels = pattern.split(".")
    hostname_labels = hostname.split(".")
    return (
        len(pattern_labels) == len(hostname_labels)
        and pattern_labels[0] == "*"
        and pattern_labels[1:] == hostname_labels[1:]
    )


def certificate_matches_hostname(decoded, hostname):
    """Best-effort hostname/IP matching without deprecated ssl.match_hostname()."""
    if not decoded or not hostname:
        return None

    hostname = strip_address_brackets(hostname).rstrip(".")
    subject_alt_names = decoded.get("subjectAltName") or ()

    if is_ip_literal(hostname):
        expected_ip = ipaddress.ip_address(hostname)
        ip_names = [
            value
            for name_type, value in subject_alt_names
            if name_type in {"IP Address", "IP"}
        ]
        if not ip_names:
            return False
        for value in ip_names:
            try:
                if ipaddress.ip_address(value) == expected_ip:
                    return True
            except ValueError:
                continue
        return False

    dns_names = [
        value
        for name_type, value in subject_alt_names
        if name_type == "DNS"
    ]
    candidates = dns_names
    if not candidates:
        common_name = certificate_name_value(decoded.get("subject"), "commonName")
        candidates = [common_name] if common_name else []

    if not candidates:
        return False
    return any(dns_pattern_matches(pattern, hostname) for pattern in candidates)


def decode_certificate(der_certificate, hostname=None):
    """Return compact certificate details using only Python's standard library."""
    if not der_certificate:
        return []

    details = []
    decoded = None
    temporary_path = None

    # _test_decode_cert is private but widely available in CPython. Keep this
    # best-effort so TLS scanning still works if an interpreter omits it.
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is not None:
        try:
            pem = ssl.DER_cert_to_PEM_cert(der_certificate)
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pem", delete=False, encoding="ascii"
            ) as temporary_file:
                temporary_file.write(pem)
                temporary_path = temporary_file.name
            decoded = decoder(temporary_path)
        except (OSError, ValueError, ssl.SSLError):
            decoded = None
        finally:
            if temporary_path:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass

    if decoded:
        subject_cn = certificate_name_value(decoded.get("subject"), "commonName")
        issuer_cn = certificate_name_value(decoded.get("issuer"), "commonName")

        if subject_cn:
            details.append("CN={}".format(subject_cn))
        if issuer_cn and issuer_cn != subject_cn:
            details.append("issuer={}".format(issuer_cn))

        not_after = decoded.get("notAfter")
        if not_after:
            try:
                expiry_timestamp = ssl.cert_time_to_seconds(not_after)
                expiry_date = datetime.fromtimestamp(
                    expiry_timestamp, timezone.utc
                ).date().isoformat()
                if expiry_timestamp < time.time():
                    details.append("CERT EXPIRED {}".format(expiry_date))
                else:
                    details.append("cert expires {}".format(expiry_date))
            except (TypeError, ValueError, OverflowError):
                pass

        hostname_matches = certificate_matches_hostname(decoded, hostname)
        if hostname_matches is False:
            details.append("hostname mismatch")

    if not details:
        fingerprint = hashlib.sha256(der_certificate).hexdigest()[:16]
        details.append("cert SHA256 {}".format(fingerprint))

    return details


def probe_tls(target, ip, port, timeout, probe_https=False):
    """Perform a TLS handshake and optionally send an HTTPS HEAD request."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    server_hostname = None if is_ip_literal(target) else target.rstrip(".")

    with socket.create_connection((strip_address_brackets(ip), port), timeout=timeout) as raw_socket:
        raw_socket.settimeout(timeout)
        with context.wrap_socket(
            raw_socket,
            server_hostname=server_hostname,
        ) as tls_socket:
            tls_version = tls_socket.version() or "TLS"
            cipher_info = tls_socket.cipher()
            cipher_name = cipher_info[0] if cipher_info else ""
            der_certificate = tls_socket.getpeercert(binary_form=True)

            response = b""
            if probe_https:
                try:
                    # GET is more widely implemented by minimal/debug HTTPS
                    # servers than HEAD. Only the response headers are retained.
                    tls_socket.sendall(
                        build_http_request(
                            target,
                            port,
                            secure=True,
                            method="GET",
                        )
                    )
                    response = receive_response(tls_socket)
                except (socket.timeout, OSError, ssl.SSLError):
                    response = b""

            service = COMMON_PORTS.get(port, "TLS")
            response_banner = http_response_banner(response)
            if response_banner:
                service = "HTTPS"

            details = []
            if response_banner:
                details.append(response_banner)
            details.append(tls_version)
            if cipher_name:
                details.append(cipher_name)
            details.extend(
                decode_certificate(der_certificate, hostname=target)
            )

            return service, " | ".join(details)[:160]


def identify_service(target, ip, port, timeout):
    """
    Perform best-effort service identification on an already-open port.

    The original target name is retained for HTTP Host headers and TLS SNI.
    Conventional TLS ports receive a real TLS handshake. On unknown ports, TLS
    is attempted before plain HTTP so an HTTPS service is not polluted by a
    plaintext request. Other known services receive passive banner detection.
    """
    service = COMMON_PORTS.get(port, "unknown")

    if port in TLS_PROBE_PORTS:
        try:
            return probe_tls(
                target,
                ip,
                port,
                timeout,
                probe_https=port in HTTPS_PROBE_PORTS,
            )
        except (ConnectionError, OSError, socket.timeout, ssl.SSLError):
            # Preserve the fallback label if the TLS handshake fails. Some
            # devices use nonstandard configurations or obsolete TLS versions.
            return service, "TLS handshake failed"

    # First listen passively. Protocols such as SSH, FTP, SMTP, POP3, IMAP, and
    # Telnet often identify themselves immediately after a TCP connection.
    data = b""
    try:
        family = address_family(ip)
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(socket_endpoint(ip, port))
            sock.settimeout(min(timeout, 0.8))
            try:
                data = sock.recv(2048)
            except socket.timeout:
                data = b""
    except (ConnectionError, OSError, socket.timeout):
        data = b""

    upper_data = data[:16].upper()
    response_banner = http_response_banner(data)
    if response_banner:
        return "HTTP", response_banner[:160]
    if upper_data.startswith(b"SSH-"):
        return "SSH", readable_banner(data, port)[:160]
    if data:
        return service, readable_banner(data, port)[:160]

    # Unknown silent services may use TLS on nonstandard ports. Try a fresh TLS
    # connection before sending plaintext HTTP.
    if service == "unknown":
        try:
            return probe_tls(target, ip, port, timeout, probe_https=True)
        except (ConnectionError, OSError, socket.timeout, ssl.SSLError):
            pass

    # Plain HTTP is appropriate on conventional web ports and is a final
    # best-effort probe for an otherwise unknown silent service.
    if port in HTTP_PROBE_PORTS or service == "unknown":
        try:
            with socket.create_connection(
                (strip_address_brackets(ip), port), timeout=timeout
            ) as sock:
                sock.settimeout(timeout)
                sock.sendall(
                    build_http_request(target, port, secure=False, method="HEAD")
                )
                data = receive_response(sock)
            response_banner = http_response_banner(data)
            if response_banner:
                return "HTTP", response_banner[:160]
            if data:
                return service, readable_banner(data, port)[:160]
        except (ConnectionError, OSError, socket.timeout):
            pass

    return service, ""


def _service_future_result(future, result):
    """Apply one completed service-identification future to its result row."""
    try:
        service, banner = future.result()
        result["service"] = service
        result["banner"] = banner
    except Exception as exc:
        result["banner"] = "identification error: {}".format(exc)


def identify_open_services(
    target,
    ip,
    results,
    timeout,
    max_workers=10,
    progress=True,
):
    """Identify open services concurrently and preserve work on Ctrl+C."""
    open_results = [result for result in results if result["state"] == "open"]
    if not open_results:
        return

    worker_count = min(max_workers, len(open_results))
    pool = ThreadPoolExecutor(max_workers=worker_count)
    future_to_result = {}
    processed = set()
    completed_count = 0

    try:
        for result in open_results:
            future = pool.submit(
                identify_service,
                target,
                ip,
                result["port"],
                timeout,
            )
            future_to_result[future] = result

        for future in as_completed(future_to_result):
            processed.add(future)
            _service_future_result(future, future_to_result[future])
            completed_count += 1

            if progress and len(open_results) > 1:
                print(
                    "\r  identified {}/{} open service(s)...".format(
                        completed_count, len(open_results)
                    ),
                    end="",
                    flush=True,
                )

    except KeyboardInterrupt:
        # Preserve any futures that completed just before the interrupt but were
        # not yet yielded by as_completed().
        for future, result in future_to_result.items():
            if future in processed or future.cancelled() or not future.done():
                continue
            processed.add(future)
            _service_future_result(future, result)
            completed_count += 1

        for future in future_to_result:
            if not future.done():
                future.cancel()
        pool.shutdown(wait=False, cancel_futures=True)

        if progress and len(open_results) > 1:
            print(
                "\r  service identification interrupted after {}/{}.{}".format(
                    completed_count, len(open_results), " " * 12
                )
            )
        raise ScanInterrupted(
            results,
            stage="service identification",
            stage_completed=completed_count,
            stage_total=len(open_results),
        )
    except BaseException:
        for future in future_to_result:
            if not future.done():
                future.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True)

    if progress and len(open_results) > 1:
        print(
            "\r  identified {}/{} open service(s).{}".format(
                len(open_results), len(open_results), " " * 12
            )
        )


# ---------------------------------------------------------------------------
# Engine 1: multithreaded TCP connect scan
# ---------------------------------------------------------------------------


def make_result(port, state, reason, service=None, banner=""):
    """Create one consistently shaped result dictionary."""
    return {
        "port": port,
        "state": state,
        "service": service or (
            COMMON_PORTS.get(port, "unknown") if state == "open" else "unknown"
        ),
        "banner": banner,
        "reason": reason,
    }


def _connect_probe(ip, port, timeout, retries=1):
    """Probe one TCP port and return its state and reason."""
    last_error = None

    for attempt in range(retries + 1):
        try:
            # connect() gives Python a chance to turn a timed-out operation into
            # TimeoutError instead of exposing a platform-specific connect_ex()
            # errno such as EAGAIN.
            family = address_family(ip)
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(socket_endpoint(ip, port))
            return make_result(port, "open", "connection succeeded")

        except ConnectionRefusedError:
            return make_result(port, "closed", "connection refused")
        except (socket.timeout, TimeoutError):
            return make_result(port, "filtered", "timeout")
        except OSError as exc:
            error_code = exc.errno
            last_error = error_code

            if error_code == errno.ECONNREFUSED:
                return make_result(port, "closed", "connection refused")

            if error_code in AMBIGUOUS_CONNECT_ERRORS:
                if attempt < retries:
                    time.sleep(0.02 * (attempt + 1))
                    continue
                return make_result(
                    port,
                    "filtered",
                    "connection did not complete: {}".format(
                        os.strerror(error_code) if error_code else str(exc)
                    ),
                )

            if error_code in TRANSIENT_LOCAL_ERRORS:
                if attempt < retries:
                    time.sleep(0.02 * (attempt + 1))
                    continue
                return make_result(
                    port,
                    "error",
                    "local scanner resource error: {}".format(
                        os.strerror(error_code)
                    ),
                )

            return make_result(port, "filtered", str(exc))

    return make_result(port, "error", "probe failed: {}".format(last_error))


def _connect_future_result(future, port):
    """Convert a completed connect-scan future into a stable result row."""
    try:
        return future.result()
    except Exception as exc:
        return make_result(port, "error", "probe failed: {}".format(exc))


def tcp_connect_scan(
    ip,
    ports,
    timeout=1.0,
    max_threads=100,
    retries=1,
    progress=True,
):
    """Scan TCP ports concurrently and preserve completed rows on Ctrl+C."""
    results = []
    total = len(ports)
    pool = ThreadPoolExecutor(max_workers=max_threads)
    future_to_port = {}
    processed = set()

    try:
        for port in ports:
            future = pool.submit(_connect_probe, ip, port, timeout, retries)
            future_to_port[future] = port

        for future in as_completed(future_to_port):
            processed.add(future)
            results.append(
                _connect_future_result(future, future_to_port[future])
            )
            completed = len(results)

            if progress and (completed % 50 == 0 or completed == total):
                print(
                    "\r  scanned {}/{} ports...".format(completed, total),
                    end="",
                    flush=True,
                )

    except KeyboardInterrupt:
        # Some futures may have completed between the last as_completed() yield
        # and Ctrl+C. Keep those rows before cancelling queued work.
        for future, port in future_to_port.items():
            if future in processed or future.cancelled() or not future.done():
                continue
            processed.add(future)
            results.append(_connect_future_result(future, port))

        for future in future_to_port:
            if not future.done():
                future.cancel()
        pool.shutdown(wait=False, cancel_futures=True)

        results.sort(key=lambda result: result["port"])
        if progress:
            print(
                "\r  scan interrupted after {}/{} completed port(s).{}".format(
                    len(results), total, " " * 12
                )
            )
        raise ScanInterrupted(
            results,
            stage="TCP connect scan",
            stage_completed=len(results),
            stage_total=total,
        )
    except BaseException:
        for future in future_to_port:
            if not future.done():
                future.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True)

    if progress:
        print("\r  scanned {}/{} ports.{}".format(total, total, " " * 15))

    return sorted(results, key=lambda result: result["port"])


# ---------------------------------------------------------------------------
# Engine 2: rate-controlled batched half-open SYN scan
# ---------------------------------------------------------------------------


def classify_syn_response(response):
    """Classify a Scapy response as open, closed, or filtered."""
    if response.haslayer(TCP):
        flags = int(response[TCP].flags)

        # 0x12 is SYN (0x02) + ACK (0x10).
        if (flags & 0x12) == 0x12:
            return "open", "SYN-ACK"

        # 0x04 is RST.
        if flags & 0x04:
            return "closed", "RST"

        return "filtered", "unexpected TCP flags {}".format(response[TCP].flags)

    if response.haslayer(ICMP):
        icmp = response[ICMP]
        return (
            "filtered",
            "ICMP type {} code {}".format(int(icmp.type), int(icmp.code)),
        )

    for layer in ICMPV6_ERROR_LAYERS:
        if response.haslayer(layer):
            icmp = response[layer]
            return (
                "filtered",
                "ICMPv6 type {} code {}".format(
                    int(getattr(icmp, "type", -1)),
                    int(getattr(icmp, "code", 0)),
                ),
            )

    return "filtered", "unexpected response"


def network_layer(ip):
    """Create the matching Scapy IPv4 or IPv6 network layer."""
    address = strip_address_brackets(ip)
    if address_family(address) == socket.AF_INET6:
        return IPv6(dst=address)
    return IP(dst=address)


def build_syn_packets(ip, ports):
    """Create IPv4/IPv6 SYN packets with randomized source ports."""
    packets = []
    used_source_ports = set()

    for port in ports:
        source_port = random.randint(32768, 60999)
        while source_port in used_source_ports:
            source_port = random.randint(32768, 60999)
        used_source_ports.add(source_port)

        packets.append(
            network_layer(ip)
            / TCP(
                sport=source_port,
                dport=port,
                flags="S",
                seq=random.randint(0, 2**32 - 1),
            )
        )

    return packets


def syn_scan(
    ip,
    ports,
    timeout=1.0,
    batch_size=512,
    retries=1,
    inter=0.001,
    progress=True,
):
    """
    Scan TCP ports using rate-controlled Scapy SYN batches.

    A large burst can make routers, access points, or the local Wi-Fi path drop
    replies. Unanswered ports are therefore retried in progressively smaller,
    slower batches. A port is marked filtered only after every attempt fails to
    obtain a response. Ctrl+C preserves every response classified so far.
    """
    if not SCAPY_AVAILABLE and not load_scapy():
        detail = "" if SCAPY_IMPORT_ERROR is None else ": {}".format(
            SCAPY_IMPORT_ERROR
        )
        raise RuntimeError(
            "Scapy is unavailable{}. Activate the virtual environment and run "
            "'pip install -r requirements.txt'.".format(detail)
        )

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError(
            "SYN scanning needs raw-socket privileges. Re-run with sudo, for "
            "example: sudo .venv/bin/portscan TARGET --syn"
        )

    conf.verb = 0
    results_by_port = {}
    pending_ports = list(ports)
    total = len(ports)
    total_replies = 0

    try:
        for attempt in range(retries + 1):
            if not pending_ports:
                break

            attempt_batch_size = max(32, batch_size // (2**attempt))
            attempt_inter = inter * (2**attempt)
            attempt_timeout = timeout * (1.0 + 0.5 * attempt)
            unanswered_ports = []
            attempted_this_round = 0

            if progress and attempt > 0:
                print(
                    "  retry {}/{}: {} unanswered port(s)".format(
                        attempt, retries, len(pending_ports)
                    )
                )

            for port_batch in chunked(pending_ports, attempt_batch_size):
                packets = build_syn_packets(ip, port_batch)

                answered, unanswered = sr(
                    packets,
                    timeout=attempt_timeout,
                    retry=0,
                    inter=attempt_inter,
                    verbose=0,
                    threaded=True,
                )

                total_replies += len(answered)
                reset_packets = []

                for sent_packet, response in answered:
                    port = int(sent_packet[TCP].dport)
                    state, reason = classify_syn_response(response)
                    results_by_port[port] = make_result(port, state, reason)

                    if state == "open" and response.haslayer(TCP):
                        reset_packets.append(
                            network_layer(ip)
                            / TCP(
                                sport=int(sent_packet[TCP].sport),
                                dport=port,
                                flags="R",
                                seq=int(response[TCP].ack),
                            )
                        )

                if reset_packets:
                    send(reset_packets, verbose=0)

                unanswered_ports.extend(
                    int(sent_packet[TCP].dport) for sent_packet in unanswered
                )
                attempted_this_round += len(port_batch)

                if progress and attempt == 0:
                    print(
                        "\r  scanned {}/{} ports...".format(
                            attempted_this_round, total
                        ),
                        end="",
                        flush=True,
                    )

            pending_ports = sorted(set(unanswered_ports))

    except KeyboardInterrupt:
        partial_results = [
            results_by_port[port] for port in sorted(results_by_port)
        ]
        if progress:
            print(
                "\r  SYN scan interrupted after {}/{} classified port(s).{}".format(
                    len(partial_results), total, " " * 12
                )
            )
        raise ScanInterrupted(
            partial_results,
            stage="SYN scan",
            stage_completed=len(partial_results),
            stage_total=total,
        )

    if progress:
        print("\r  scanned {}/{} ports.{}".format(total, total, " " * 15))

    for port in pending_ports:
        results_by_port[port] = make_result(
            port,
            "filtered",
            "no response after {} attempt(s)".format(retries + 1),
        )

    # Defensive fallback: ensure every requested port is represented.
    for port in ports:
        results_by_port.setdefault(
            port,
            make_result(port, "filtered", "no classified response"),
        )

    if total_replies == 0:
        print(
            "  Note: the target returned no replies. It may be offline, at a "
            "different address, or silently filtering the scan."
        )

    return [results_by_port[port] for port in sorted(results_by_port)]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def get_state_counts(results):
    return Counter(result["state"] for result in results)


def select_results(results, show_all):
    """Select rows for terminal display."""
    if show_all:
        return list(results)
    return [result for result in results if result["state"] == "open"]


def select_report_results(results, open_only):
    """Select rows for a saved report independently of terminal display."""
    if open_only:
        return [result for result in results if result["state"] == "open"]
    return list(results)


def summary_dict(counts):
    """Return stable JSON-friendly state totals, including any future states."""
    summary = {
        state: int(counts.get(state, 0))
        for state in ("open", "closed", "filtered", "error")
    }
    for state, count in sorted(counts.items()):
        if state not in summary:
            summary[state] = int(count)
    return summary


def summary_text(counts):
    summary = summary_dict(counts)
    parts = [
        "{} open".format(summary["open"]),
        "{} closed".format(summary["closed"]),
        "{} filtered".format(summary["filtered"]),
    ]
    if summary["error"]:
        parts.append("{} error".format(summary["error"]))
    for state, count in summary.items():
        if state not in {"open", "closed", "filtered", "error"} and count:
            parts.append("{} {}".format(count, state))
    return ", ".join(parts)


def result_detail(result):
    """Return the most useful human-readable detail for one result."""
    if result["state"] == "open":
        return result.get("banner", "")
    return result.get("reason", "")


def normalized_result(result):
    """Return a stable, serializable representation of one port result."""
    return {
        "port": int(result.get("port", 0)),
        "state": str(result.get("state", "unknown")),
        "service": str(result.get("service", "unknown")),
        "banner": str(result.get("banner", "")),
        "reason": str(result.get("reason", "")),
    }


def resolve_output_format(path, requested_format="auto"):
    """Resolve report format explicitly or from the output filename extension."""
    requested_format = requested_format.lower()
    if requested_format not in REPORT_FORMATS:
        raise ValueError("unsupported output format: {}".format(requested_format))
    if requested_format != "auto":
        return requested_format

    extension = os.path.splitext(os.fspath(path))[1].lower()
    return {
        ".json": "json",
        ".csv": "csv",
        ".txt": "text",
        ".log": "text",
    }.get(extension, "text")


def report_progress(results, ports_requested=None):
    """Return completed/requested counts and a bounded completion percentage."""
    completed = len(results)
    requested = completed if ports_requested is None else max(0, int(ports_requested))
    if requested == 0:
        percent = 100.0 if completed == 0 else 0.0
    else:
        percent = min(100.0, (completed / requested) * 100.0)
    return completed, requested, round(percent, 4)


def build_report_document(
    target,
    ip,
    results,
    elapsed,
    scan_type,
    started_at,
    finished_at,
    open_only=False,
    profile=DEFAULT_PROFILE,
    effective_settings=None,
    profile_overrides=None,
    status="completed",
    interrupted_stage=None,
    ports_requested=None,
    stage_completed=None,
    stage_total=None,
):
    """Build the structured document used by JSON reports."""
    report_results = select_report_results(results, open_only)
    counts = get_state_counts(results)
    completed, requested, percent = report_progress(results, ports_requested)
    stage_progress = None
    if stage_completed is not None or stage_total is not None:
        stage_progress = {
            "completed": int(stage_completed or 0),
            "total": int(stage_total or 0),
        }

    return {
        "scanner": {
            "name": SCANNER_NAME,
            "version": SCANNER_VERSION,
        },
        "target": {
            "input": target,
            "resolved_ip": ip,
            "address_family": address_family_name(ip),
        },
        "scan": {
            "type": scan_type,
            "status": status,
            "interrupted": status == "interrupted",
            "interrupted_stage": interrupted_stage,
            "started_at": started_at.isoformat(timespec="seconds"),
            "finished_at": finished_at.isoformat(timespec="seconds"),
            "duration_seconds": round(float(elapsed), 6),
            "ports_scanned": completed,
            "ports_requested": requested,
            "ports_completed": completed,
            "completion_percent": percent,
            "stage_progress": stage_progress,
            "report_scope": "open-only" if open_only else "all-states",
            "results_written": len(report_results),
            "profile": profile,
            "profile_overrides": list(profile_overrides or []),
            "effective_settings": normalized_scan_settings(effective_settings),
        },
        "summary": summary_dict(counts),
        "results": [normalized_result(result) for result in report_results],
    }


def print_results(
    target,
    ip,
    results,
    elapsed,
    scan_type,
    show_all=False,
    status="completed",
    interrupted_stage=None,
    ports_requested=None,
):
    displayed = select_results(results, show_all)
    counts = get_state_counts(results)
    completed, requested, percent = report_progress(results, ports_requested)

    print()
    print("=" * 76)
    print("  Scan report for {} ({})".format(target, ip))
    print("  Scan type : {}".format(scan_type))
    if status != "completed":
        print("  Status    : {} during {}".format(
            status, interrupted_stage or "scan"
        ))
        print("  Progress  : {}/{} port result(s) ({:.2f}%)".format(
            completed, requested, percent
        ))
    print("  Duration  : {:.2f}s".format(elapsed))
    print("  Summary   : {}".format(summary_text(counts)))
    print("=" * 76)

    if not displayed:
        if show_all:
            print("\n  No results were produced.\n")
        else:
            print("\n  No open ports found in the completed results.\n")
        return

    print("\n  {:<8}{:<11}{:<18}{}".format(
        "PORT", "STATE", "SERVICE", "BANNER / REASON"
    ))
    print("  {:<8}{:<11}{:<18}{}".format(
        "------", "--------", "---------------", "------------------------------------"
    ))

    for result in displayed:
        detail = result_detail(result)
        if len(detail) > 120:
            detail = detail[:119] + "…"

        print("  {:<8}{:<11}{:<18}{}".format(
            result["port"],
            result["state"],
            result["service"],
            detail,
        ))

    if not show_all:
        print("\n  Showing open ports only. Use --show-all for every state.")
    print()


def write_text_report(
    path,
    target,
    ip,
    results,
    elapsed,
    scan_type,
    started_at,
    finished_at,
    open_only=False,
    profile=DEFAULT_PROFILE,
    effective_settings=None,
    profile_overrides=None,
    status="completed",
    interrupted_stage=None,
    ports_requested=None,
    stage_completed=None,
    stage_total=None,
):
    report_results = select_report_results(results, open_only)
    counts = get_state_counts(results)
    completed, requested, percent = report_progress(results, ports_requested)

    with open(path, "w", encoding="utf-8") as report:
        report.write("Port scan report\n")
        report.write("Scanner   : {} {}\n".format(SCANNER_NAME, SCANNER_VERSION))
        report.write("Target    : {} ({})\n".format(target, ip))
        report.write("Family    : {}\n".format(address_family_name(ip)))
        report.write("Scan type : {}\n".format(scan_type))
        report.write("Status    : {}\n".format(status))
        if interrupted_stage:
            report.write("Interrupted: {}\n".format(interrupted_stage))
        report.write("Progress  : {}/{} port result(s) ({:.2f}%)\n".format(
            completed, requested, percent
        ))
        if stage_completed is not None or stage_total is not None:
            report.write("Stage     : {}/{} completed\n".format(
                int(stage_completed or 0), int(stage_total or 0)
            ))
        report.write("Profile   : {}\n".format(profile))
        report.write("Overrides : {}\n".format(
            ", ".join(profile_overrides or []) or "none"
        ))
        settings = normalized_scan_settings(effective_settings)
        report.write(
            "Settings  : timeout={:g}s, threads={}, batch-size={}, "
            "inter={:g}s, retries={}\n".format(
                settings["timeout"],
                settings["threads"],
                settings["batch_size"],
                settings["inter"],
                settings["retries"],
            )
        )
        report.write("Started   : {}\n".format(
            started_at.isoformat(timespec="seconds")
        ))
        report.write("Finished  : {}\n".format(
            finished_at.isoformat(timespec="seconds")
        ))
        report.write("Duration  : {:.6f}s\n".format(elapsed))
        report.write("Ports     : {} of {} completed\n".format(completed, requested))
        report.write("Scope     : {}\n".format(
            "open ports only" if open_only else "all states"
        ))
        report.write("Summary   : {}\n\n".format(summary_text(counts)))
        report.write("{:<8}{:<11}{:<18}{:<42}{}\n".format(
            "PORT", "STATE", "SERVICE", "BANNER", "REASON"
        ))

        for result in report_results:
            normalized = normalized_result(result)
            report.write("{:<8}{:<11}{:<18}{:<42}{}\n".format(
                normalized["port"],
                normalized["state"],
                normalized["service"],
                normalized["banner"],
                normalized["reason"],
            ))


def write_json_report(
    path,
    target,
    ip,
    results,
    elapsed,
    scan_type,
    started_at,
    finished_at,
    open_only=False,
    profile=DEFAULT_PROFILE,
    effective_settings=None,
    profile_overrides=None,
    status="completed",
    interrupted_stage=None,
    ports_requested=None,
    stage_completed=None,
    stage_total=None,
):
    document = build_report_document(
        target,
        ip,
        results,
        elapsed,
        scan_type,
        started_at,
        finished_at,
        open_only=open_only,
        profile=profile,
        effective_settings=effective_settings,
        profile_overrides=profile_overrides,
        status=status,
        interrupted_stage=interrupted_stage,
        ports_requested=ports_requested,
        stage_completed=stage_completed,
        stage_total=stage_total,
    )
    with open(path, "w", encoding="utf-8") as report:
        json.dump(document, report, indent=2, ensure_ascii=False)
        report.write("\n")


def write_csv_report(
    path,
    target,
    ip,
    results,
    elapsed,
    scan_type,
    started_at,
    finished_at,
    open_only=False,
    profile=DEFAULT_PROFILE,
    effective_settings=None,
    profile_overrides=None,
    status="completed",
    interrupted_stage=None,
    ports_requested=None,
    stage_completed=None,
    stage_total=None,
):
    report_results = select_report_results(results, open_only)
    completed, requested, percent = report_progress(results, ports_requested)
    fieldnames = [
        "scanner_version",
        "target",
        "resolved_ip",
        "address_family",
        "scan_type",
        "scan_status",
        "interrupted_stage",
        "ports_requested",
        "ports_completed",
        "completion_percent",
        "stage_completed",
        "stage_total",
        "started_at",
        "duration_seconds",
        "profile",
        "profile_overrides",
        "timeout",
        "threads",
        "batch_size",
        "inter",
        "retries",
        "port",
        "state",
        "service",
        "banner",
        "reason",
    ]

    settings = normalized_scan_settings(effective_settings)
    common = {
        "scanner_version": SCANNER_VERSION,
        "target": target,
        "resolved_ip": ip,
        "address_family": address_family_name(ip),
        "scan_type": scan_type,
        "scan_status": status,
        "interrupted_stage": interrupted_stage or "",
        "ports_requested": requested,
        "ports_completed": completed,
        "completion_percent": "{:.4f}".format(percent),
        "stage_completed": "" if stage_completed is None else int(stage_completed),
        "stage_total": "" if stage_total is None else int(stage_total),
        "started_at": started_at.isoformat(timespec="seconds"),
        "duration_seconds": "{:.6f}".format(elapsed),
        "profile": profile,
        "profile_overrides": ",".join(profile_overrides or []),
        **settings,
    }

    with open(path, "w", encoding="utf-8", newline="") as report:
        writer = csv.DictWriter(report, fieldnames=fieldnames)
        writer.writeheader()
        for result in report_results:
            writer.writerow({**common, **normalized_result(result)})


def write_report(
    path,
    target,
    ip,
    results,
    elapsed,
    scan_type,
    started_at,
    finished_at,
    output_format="auto",
    open_only=False,
    profile=DEFAULT_PROFILE,
    effective_settings=None,
    profile_overrides=None,
    status="completed",
    interrupted_stage=None,
    ports_requested=None,
    stage_completed=None,
    stage_total=None,
):
    """Write a complete or partial report and return format and row count."""
    resolved_format = resolve_output_format(path, output_format)
    writers = {
        "text": write_text_report,
        "json": write_json_report,
        "csv": write_csv_report,
    }
    writers[resolved_format](
        path,
        target,
        ip,
        results,
        elapsed,
        scan_type,
        started_at,
        finished_at,
        open_only=open_only,
        profile=profile,
        effective_settings=effective_settings,
        profile_overrides=profile_overrides,
        status=status,
        interrupted_stage=interrupted_stage,
        ports_requested=ports_requested,
        stage_completed=stage_completed,
        stage_total=stage_total,
    )
    return resolved_format, len(select_report_results(results, open_only))



def aggregate_state_counts(target_runs):
    """Combine port-state counts across target runs."""
    counts = Counter()
    for run in target_runs:
        counts.update(get_state_counts(run.get("results", [])))
    return counts


def build_batch_report_document(
    target_runs,
    scan_type,
    started_at,
    finished_at,
    elapsed,
    ports_per_target,
    targets_requested,
    planned_probes,
    open_only=False,
    profile=DEFAULT_PROFILE,
    effective_settings=None,
    profile_overrides=None,
    status="completed",
):
    """Build a structured multi-target JSON report."""
    documents = []
    for run in target_runs:
        document = build_report_document(
            run["target"],
            run["ip"],
            run["results"],
            run["elapsed"],
            scan_type,
            run["started_at"],
            run["finished_at"],
            open_only=open_only,
            profile=profile,
            effective_settings=effective_settings,
            profile_overrides=profile_overrides,
            status=run["status"],
            interrupted_stage=run.get("interrupted_stage"),
            ports_requested=ports_per_target,
            stage_completed=run.get("stage_completed"),
            stage_total=run.get("stage_total"),
        )
        document["target"]["expanded_from"] = run.get("expanded_from")
        documents.append(document)

    completed_probes = sum(len(run.get("results", [])) for run in target_runs)
    completed_targets = sum(1 for run in target_runs if run["status"] == "completed")
    report_rows = sum(len(document["results"]) for document in documents)
    return {
        "scanner": {"name": SCANNER_NAME, "version": SCANNER_VERSION},
        "batch": {
            "status": status,
            "interrupted": status == "interrupted",
            "started_at": started_at.isoformat(timespec="seconds"),
            "finished_at": finished_at.isoformat(timespec="seconds"),
            "duration_seconds": round(float(elapsed), 6),
            "targets_requested": int(targets_requested),
            "targets_started": len(target_runs),
            "targets_completed": completed_targets,
            "ports_per_target": int(ports_per_target),
            "planned_probes": int(planned_probes),
            "completed_probes": completed_probes,
            "completion_percent": round(
                (completed_probes / planned_probes) * 100.0, 4
            ) if planned_probes else 100.0,
            "report_scope": "open-only" if open_only else "all-states",
            "results_written": report_rows,
            "profile": profile,
            "profile_overrides": list(profile_overrides or []),
            "effective_settings": normalized_scan_settings(effective_settings),
        },
        "summary": summary_dict(aggregate_state_counts(target_runs)),
        "targets": documents,
    }


def write_batch_json_report(path, document):
    with open(path, "w", encoding="utf-8") as report:
        json.dump(document, report, indent=2, ensure_ascii=False)
        report.write("\n")


def write_batch_text_report(path, document):
    batch = document["batch"]
    with open(path, "w", encoding="utf-8") as report:
        report.write("Multi-target port scan report\n")
        report.write("Scanner    : {} {}\n".format(SCANNER_NAME, SCANNER_VERSION))
        report.write("Status     : {}\n".format(batch["status"]))
        report.write("Targets    : {} started, {} completed, {} requested\n".format(
            batch["targets_started"],
            batch["targets_completed"],
            batch["targets_requested"],
        ))
        report.write("Probes     : {}/{} completed ({:.2f}%)\n".format(
            batch["completed_probes"],
            batch["planned_probes"],
            batch["completion_percent"],
        ))
        report.write("Started    : {}\n".format(batch["started_at"]))
        report.write("Finished   : {}\n".format(batch["finished_at"]))
        report.write("Duration   : {:.6f}s\n".format(batch["duration_seconds"]))
        report.write("Summary    : {}\n\n".format(
            summary_text(Counter(document["summary"]))
        ))
        for index, target_document in enumerate(document["targets"], start=1):
            target = target_document["target"]
            scan = target_document["scan"]
            report.write("=" * 88 + "\n")
            report.write("Target {}/{}: {} ({}) [{}]\n".format(
                index,
                len(document["targets"]),
                target["input"],
                target["resolved_ip"],
                target["address_family"],
            ))
            if target.get("expanded_from"):
                report.write("Expanded from: {}\n".format(target["expanded_from"]))
            report.write("Status: {} | Duration: {:.6f}s | Summary: {}\n".format(
                scan["status"],
                scan["duration_seconds"],
                summary_text(Counter(target_document["summary"])),
            ))
            report.write("{:<8}{:<11}{:<18}{:<42}{}\n".format(
                "PORT", "STATE", "SERVICE", "BANNER", "REASON"
            ))
            for result in target_document["results"]:
                report.write("{:<8}{:<11}{:<18}{:<42}{}\n".format(
                    result["port"], result["state"], result["service"],
                    result["banner"], result["reason"]
                ))
            report.write("\n")


def write_batch_csv_report(path, document):
    fieldnames = [
        "scanner_version", "batch_status", "target_index", "targets_requested",
        "target", "expanded_from", "resolved_ip", "address_family",
        "scan_type", "scan_status", "started_at", "duration_seconds",
        "profile", "port", "state", "service", "banner", "reason",
    ]
    with open(path, "w", encoding="utf-8", newline="") as report:
        writer = csv.DictWriter(report, fieldnames=fieldnames)
        writer.writeheader()
        for index, target_document in enumerate(document["targets"], start=1):
            target = target_document["target"]
            scan = target_document["scan"]
            common = {
                "scanner_version": SCANNER_VERSION,
                "batch_status": document["batch"]["status"],
                "target_index": index,
                "targets_requested": document["batch"]["targets_requested"],
                "target": target["input"],
                "expanded_from": target.get("expanded_from") or "",
                "resolved_ip": target["resolved_ip"],
                "address_family": target["address_family"],
                "scan_type": scan["type"],
                "scan_status": scan["status"],
                "started_at": scan["started_at"],
                "duration_seconds": scan["duration_seconds"],
                "profile": scan["profile"],
            }
            for result in target_document["results"]:
                writer.writerow({**common, **normalized_result(result)})


def write_batch_report(
    path,
    target_runs,
    scan_type,
    started_at,
    finished_at,
    elapsed,
    ports_per_target,
    targets_requested,
    planned_probes,
    output_format="auto",
    open_only=False,
    profile=DEFAULT_PROFILE,
    effective_settings=None,
    profile_overrides=None,
    status="completed",
):
    """Write one report containing all target results."""
    resolved_format = resolve_output_format(path, output_format)
    document = build_batch_report_document(
        target_runs,
        scan_type,
        started_at,
        finished_at,
        elapsed,
        ports_per_target,
        targets_requested,
        planned_probes,
        open_only=open_only,
        profile=profile,
        effective_settings=effective_settings,
        profile_overrides=profile_overrides,
        status=status,
    )
    writers = {
        "json": write_batch_json_report,
        "text": write_batch_text_report,
        "csv": write_batch_csv_report,
    }
    writers[resolved_format](path, document)
    return resolved_format, int(document["batch"]["results_written"])


def print_batch_summary(target_runs, targets_requested, planned_probes, status):
    """Print a concise aggregate summary after a multi-target scan."""
    counts = aggregate_state_counts(target_runs)
    completed_probes = sum(len(run.get("results", [])) for run in target_runs)
    completed_targets = sum(1 for run in target_runs if run["status"] == "completed")
    print("\n" + "#" * 76)
    print("  Multi-target summary")
    print("  Status   : {}".format(status))
    print("  Targets  : {}/{} completed ({} started)".format(
        completed_targets, targets_requested, len(target_runs)
    ))
    print("  Probes   : {}/{} completed".format(completed_probes, planned_probes))
    print("  Summary  : {}".format(summary_text(counts)))
    print("#" * 76 + "\n")

# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------


EPILOG = """Examples:
  portscan 192.168.1.10 -p 1-1024
  portscan 192.168.1.10 192.168.1.20 -p 22,80,443
  portscan 192.168.1.0/28 -p 22,80,443
  portscan --targets-file targets.txt -p 1-1024
  portscan example.com -6 -p 22,80,443
  portscan 192.168.1.10 --profile fast
  sudo .venv/bin/portscan 192.168.1.0/29 --syn --profile reliable
  portscan 192.168.1.0/24 -p 80 --max-targets 254
  portscan 192.168.1.0/24 -p 1-1024 -o subnet.json
"""


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def non_negative_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def positive_float(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number")

    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def non_negative_float(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number")

    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def resolve_scan_settings(args):
    """Return profile settings after applying explicit command-line overrides."""
    profile_name = getattr(args, "profile", DEFAULT_PROFILE)
    try:
        effective = dict(SCAN_PROFILES[profile_name])
    except KeyError:
        raise ValueError("unknown scan profile: {}".format(profile_name))

    overrides = []
    for name in PROFILE_SETTING_NAMES:
        value = getattr(args, name, None)
        if value is not None:
            effective[name] = value
            overrides.append(name)

    return effective, overrides


def normalized_scan_settings(settings=None):
    """Return a stable typed representation of effective scan settings."""
    normalized = dict(SCAN_PROFILES[DEFAULT_PROFILE])
    if settings:
        for name in PROFILE_SETTING_NAMES:
            if name in settings:
                normalized[name] = settings[name]

    return {
        "timeout": float(normalized["timeout"]),
        "threads": int(normalized["threads"]),
        "batch_size": int(normalized["batch_size"]),
        "inter": float(normalized["inter"]),
        "retries": int(normalized["retries"]),
    }


def format_scan_settings(settings, syn=False):
    """Format the settings relevant to the selected scan engine."""
    settings = normalized_scan_settings(settings)
    common = "timeout={:g}s, retries={}".format(
        settings["timeout"], settings["retries"]
    )
    if syn:
        return "{}, batch-size={}, inter={:g}s".format(
            common, settings["batch_size"], settings["inter"]
        )
    return "{}, threads={}".format(common, settings["threads"])


def build_parser():
    parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]) or "portscan",
        description=(
            "IPv4/IPv6 TCP port scanner with multithreaded connect scanning and "
            "rate-controlled batched SYN scanning. Only scan authorized targets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {}".format(SCANNER_VERSION),
    )
    parser.add_argument(
        "target",
        nargs="*",
        metavar="TARGET",
        help="IPv4/IPv6 address, hostname, or CIDR range",
    )
    parser.add_argument(
        "--targets-file",
        action="append",
        default=[],
        metavar="FILE",
        help="Read targets/CIDRs from FILE; may be supplied more than once",
    )
    parser.add_argument(
        "--max-targets",
        type=positive_int,
        default=DEFAULT_MAX_TARGETS,
        help="Maximum expanded unique targets (default: 256)",
    )
    parser.add_argument(
        "--max-probes",
        type=positive_int,
        default=DEFAULT_MAX_PROBES,
        help="Maximum target-port combinations (default: 1000000)",
    )
    family_group = parser.add_mutually_exclusive_group()
    family_group.add_argument(
        "-4", "--ipv4", action="store_true",
        help="Resolve hostnames to IPv4 only",
    )
    family_group.add_argument(
        "-6", "--ipv6", action="store_true",
        help="Resolve hostnames to IPv6 only",
    )
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports such as '22,80,443' or '1-1024' (default: 1-1024)",
    )
    parser.add_argument(
        "--profile",
        choices=tuple(SCAN_PROFILES),
        default=DEFAULT_PROFILE,
        help="Scan tuning preset (default: balanced)",
    )
    parser.add_argument(
        "-t", "--timeout", type=positive_float, default=None,
        help="Override the profile timeout in seconds",
    )
    parser.add_argument(
        "--threads", type=positive_int, default=None,
        help="Override profile connect-scan worker threads",
    )
    parser.add_argument(
        "--syn", action="store_true",
        help="Use rate-controlled half-open SYN scanning through Scapy",
    )
    parser.add_argument(
        "--batch-size", type=positive_int, default=None,
        help="Override profile initial SYN packets per batch",
    )
    parser.add_argument(
        "--inter", type=non_negative_float, default=None,
        help="Override profile delay between SYN packets in seconds",
    )
    parser.add_argument(
        "--retries", type=non_negative_int, default=None,
        help="Override profile retry count for unanswered/transient probes",
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="Skip service, HTTP, and TLS identification",
    )
    parser.add_argument(
        "--banner-threads", type=positive_int, default=10,
        help="Concurrent service-identification workers (default: 10)",
    )
    parser.add_argument(
        "--show-all", action="store_true",
        help="Display closed, filtered, and error states in the terminal",
    )
    parser.add_argument(
        "--no-progress", action="store_true",
        help="Disable the live progress display",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write a complete report, or partial results after Ctrl+C",
    )
    parser.add_argument(
        "--output-format",
        choices=REPORT_FORMATS,
        default="auto",
        help="Report format (default: auto from filename extension)",
    )
    parser.add_argument(
        "--report-open-only",
        action="store_true",
        help="Save only open ports instead of all scanned port states",
    )

    return parser


def scan_one_target(
    target_entry,
    ports,
    args,
    effective_settings,
    profile_overrides,
    scan_type,
    target_index=1,
    target_total=1,
):
    """Run one target and return a reportable result bundle."""
    target = target_entry["input"]
    ip = target_entry["resolved_ip"]

    if target_total > 1:
        print("\n--- Target {}/{} ---".format(target_index, target_total))
    print("\nTarget: {} ({})".format(target, ip))
    if target_entry.get("expanded_from"):
        print("Source: {}".format(target_entry["expanded_from"]))
    print("Family: {}".format(address_family_name(ip)))
    print("Ports : {}".format(len(ports)))
    print("Mode  : {}".format(scan_type))
    override_text = ", ".join(profile_overrides) or "none"
    print("Profile: {} (overrides: {})".format(args.profile, override_text))
    print("Tuning : {}\n".format(
        format_scan_settings(effective_settings, syn=args.syn)
    ))

    scan_started_at = datetime.now().astimezone()
    started = time.perf_counter()
    results = []
    status = "completed"
    interrupted_stage = None
    stage_completed = None
    stage_total = None

    try:
        if args.syn:
            results = syn_scan(
                ip,
                ports,
                timeout=effective_settings["timeout"],
                batch_size=effective_settings["batch_size"],
                retries=effective_settings["retries"],
                inter=effective_settings["inter"],
                progress=not args.no_progress,
            )
        else:
            results = tcp_connect_scan(
                ip,
                ports,
                timeout=effective_settings["timeout"],
                max_threads=effective_settings["threads"],
                retries=effective_settings["retries"],
                progress=not args.no_progress,
            )

        if not args.no_banner:
            identify_open_services(
                target,
                ip,
                results,
                effective_settings["timeout"],
                max_workers=args.banner_threads,
                progress=not args.no_progress,
            )

    except ScanInterrupted as exc:
        results = exc.results
        status = "interrupted"
        interrupted_stage = exc.stage
        stage_completed = exc.stage_completed
        stage_total = exc.stage_total
    except KeyboardInterrupt:
        status = "interrupted"
        interrupted_stage = "scan"
        stage_completed = len(results)
        stage_total = len(ports)

    elapsed = time.perf_counter() - started
    scan_finished_at = datetime.now().astimezone()

    if status == "interrupted":
        completed, requested, percent = report_progress(results, len(ports))
        print("\nScan interrupted during {}.".format(interrupted_stage or "scan"))
        print("Preserved {}/{} port result(s) ({:.2f}%).".format(
            completed, requested, percent
        ))
        if stage_total is not None:
            print("Stage progress: {}/{}.".format(
                int(stage_completed or 0), int(stage_total)
            ))

    print_results(
        target,
        ip,
        results,
        elapsed,
        scan_type,
        show_all=args.show_all,
        status=status,
        interrupted_stage=interrupted_stage,
        ports_requested=len(ports),
    )

    return {
        "target": target,
        "ip": ip,
        "expanded_from": target_entry.get("expanded_from"),
        "results": results,
        "elapsed": elapsed,
        "started_at": scan_started_at,
        "finished_at": scan_finished_at,
        "status": status,
        "interrupted_stage": interrupted_stage,
        "stage_completed": stage_completed,
        "stage_total": stage_total,
    }


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.output and args.output_format != "auto":
        parser.error("--output-format requires --output")
    if not args.output and args.report_open_only:
        parser.error("--report-open-only requires --output")

    try:
        effective_settings, profile_overrides = resolve_scan_settings(args)
    except ValueError as exc:
        parser.error(str(exc))

    family_preference = "ipv6" if args.ipv6 else "ipv4" if args.ipv4 else "auto"
    try:
        ports = parse_ports(args.ports)
        targets = collect_targets(
            args.target,
            target_files=args.targets_file,
            family=family_preference,
            max_targets=args.max_targets,
        )
        planned_probes = validate_probe_plan(
            len(targets), len(ports), args.max_probes
        )
    except ValueError as exc:
        parser.error(str(exc))

    scan_type = (
        "SYN scan (Scapy, batched)" if args.syn else "TCP connect scan (socket)"
    )

    if len(targets) > 1:
        print("\nTargets: {} unique host(s)".format(len(targets)))
        print("Plan   : {:,} target-port probe(s)".format(planned_probes))
        print("Order  : sequential targets; concurrent ports per target")

    batch_started_at = datetime.now().astimezone()
    batch_started = time.perf_counter()
    target_runs = []
    batch_status = "completed"

    for index, target_entry in enumerate(targets, start=1):
        try:
            run = scan_one_target(
                target_entry,
                ports,
                args,
                effective_settings,
                profile_overrides,
                scan_type,
                target_index=index,
                target_total=len(targets),
            )
        except KeyboardInterrupt:
            batch_status = "interrupted"
            break
        except (RuntimeError, PermissionError, OSError) as exc:
            print("Error scanning {}: {}".format(
                target_entry["resolved_ip"], exc
            ), file=sys.stderr)
            return 1
        target_runs.append(run)
        if run["status"] == "interrupted":
            batch_status = "interrupted"
            break

    if batch_status == "interrupted" and not target_runs:
        now = datetime.now().astimezone()
        target_entry = targets[0]
        target_runs.append({
            "target": target_entry["input"],
            "ip": target_entry["resolved_ip"],
            "expanded_from": target_entry.get("expanded_from"),
            "results": [],
            "elapsed": 0.0,
            "started_at": now,
            "finished_at": now,
            "status": "interrupted",
            "interrupted_stage": "batch orchestration",
            "stage_completed": 0,
            "stage_total": len(ports),
        })

    batch_elapsed = time.perf_counter() - batch_started
    batch_finished_at = datetime.now().astimezone()

    if len(targets) > 1:
        print_batch_summary(
            target_runs, len(targets), planned_probes, batch_status
        )

    if args.output:
        try:
            if len(targets) == 1:
                run = target_runs[0]
                resolved_format, rows_written = write_report(
                    args.output,
                    run["target"],
                    run["ip"],
                    run["results"],
                    run["elapsed"],
                    scan_type,
                    run["started_at"],
                    run["finished_at"],
                    output_format=args.output_format,
                    open_only=args.report_open_only,
                    profile=args.profile,
                    effective_settings=effective_settings,
                    profile_overrides=profile_overrides,
                    status=run["status"],
                    interrupted_stage=run["interrupted_stage"],
                    ports_requested=len(ports),
                    stage_completed=run["stage_completed"],
                    stage_total=run["stage_total"],
                )
            else:
                resolved_format, rows_written = write_batch_report(
                    args.output,
                    target_runs,
                    scan_type,
                    batch_started_at,
                    batch_finished_at,
                    batch_elapsed,
                    len(ports),
                    len(targets),
                    planned_probes,
                    output_format=args.output_format,
                    open_only=args.report_open_only,
                    profile=args.profile,
                    effective_settings=effective_settings,
                    profile_overrides=profile_overrides,
                    status=batch_status,
                )
            scope = "open ports" if args.report_open_only else "all states"
            report_kind = "Partial report" if batch_status == "interrupted" else "Report"
            print("{} written to {} ({}; {} row(s); {})".format(
                report_kind, args.output, resolved_format.upper(), rows_written, scope
            ))
        except OSError as exc:
            print("Error writing report: {}".format(exc), file=sys.stderr)
            return 1
    elif batch_status == "interrupted":
        print("No partial report saved. Use -o FILE on the next scan to save one.")

    return 130 if batch_status == "interrupted" else 0

def console_main():
    """Console-script entry point installed as ``portscan``."""
    raise SystemExit(main())


if __name__ == "__main__":
    console_main()
