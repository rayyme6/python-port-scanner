"""portscanner.service_id — banner grabbing and HTTP/TLS service identification.

Runs after a scan engine has already found the open ports: reads whatever a
service says first, falls back to a HEAD request or a TLS handshake on
likely web/TLS ports, and turns a raw certificate into a short human-readable
summary using nothing but the standard library.
"""

import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from .net import address_family, is_ip_literal, socket_endpoint, strip_address_brackets
from .scan_result import COMMON_PORTS, SCANNER_NAME, SCANNER_VERSION, ScanInterrupted


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
