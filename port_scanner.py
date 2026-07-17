#!/usr/bin/env python3
"""
port_scanner.py — TCP port scanner with basic service identification.

Scan engines:
  * connect — multithreaded full TCP connections using Python sockets.
              No special privileges required.
  * syn     — rate-controlled, batched half-open SYN scanning using Scapy.
              Requires raw-socket privileges (normally sudo on Linux).

Only scan systems and networks you own or are explicitly authorized to test.

Examples:
    python3 port_scanner.py 192.168.1.10 -p 1-1024
    python3 port_scanner.py example.com -p 22,80,443 --show-all
    sudo .venv/bin/python port_scanner.py 192.168.1.10 --syn
"""

import argparse
import errno
import os
import random
import socket
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    from scapy.all import ICMP, IP, TCP, conf, send, sr

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Conventional service labels. These are fallbacks, not definitive proof of
# which application is actually listening on a port.
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    111: "RPCbind", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    631: "IPP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2375: "Docker", 3000: "Dev-HTTP",
    3306: "MySQL", 3389: "RDP", 5000: "Dev-HTTP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Plain HTTP probes are useful on likely web ports and unknown ports. They are
# intentionally not sent to known non-HTTP protocols such as DNS or Telnet.
HTTP_PROBE_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9200}

# Errors caused by temporary pressure on the scanner itself. These should be
# retried and must not be reported as if a remote firewall filtered the port.
TRANSIENT_LOCAL_ERRORS = {
    value
    for value in (
        getattr(errno, "EAGAIN", None),
        getattr(errno, "EWOULDBLOCK", None),
        getattr(errno, "ENOBUFS", None),
        getattr(errno, "ENOMEM", None),
        getattr(errno, "EMFILE", None),
        getattr(errno, "ENFILE", None),
        getattr(errno, "EADDRNOTAVAIL", None),
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


def resolve_target(target):
    """Resolve a hostname or IPv4 address to an IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError("could not resolve host '{}'".format(target))


def chunked(values, size):
    """Yield slices of values with at most size entries each."""
    for start in range(0, len(values), size):
        yield values[start:start + size]


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


def identify_service(ip, port, timeout):
    """
    Perform best-effort service identification on an already-open port.

    The scanner first waits briefly for a voluntary banner. A generic HTTP HEAD
    request is sent only to likely web ports or ports with no conventional
    service label. This avoids sending HTTP text to known services such as DNS
    and Telnet.
    """
    service = COMMON_PORTS.get(port, "unknown")
    banner = ""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            sock.settimeout(min(timeout, 0.8))
            try:
                data = sock.recv(2048)
            except socket.timeout:
                data = b""

            should_probe_http = (
                not data
                and (port in HTTP_PROBE_PORTS or service == "unknown")
            )

            if should_probe_http:
                request = (
                    "HEAD / HTTP/1.0\r\n"
                    "Host: {}\r\n"
                    "User-Agent: python-port-scanner/3.0\r\n"
                    "Connection: close\r\n\r\n"
                ).format(ip).encode()

                try:
                    sock.settimeout(timeout)
                    sock.sendall(request)
                    data = sock.recv(4096)
                except (socket.timeout, OSError):
                    data = b""

            upper_data = data[:16].upper()

            if upper_data.startswith(b"HTTP/"):
                service = "HTTP"
                text = data.decode("iso-8859-1", errors="replace")
                lines = text.splitlines()
                server_line = next(
                    (line for line in lines if line.lower().startswith("server:")),
                    None,
                )
                if server_line:
                    banner = server_line.split(":", 1)[1].strip()
                elif lines:
                    banner = " ".join(lines[0].split())
            elif upper_data.startswith(b"SSH-"):
                service = "SSH"
                banner = readable_banner(data, port)
            elif data:
                banner = readable_banner(data, port)

    except (ConnectionError, OSError, socket.timeout):
        pass

    return service, banner[:160]


def identify_open_services(ip, results, timeout):
    """Add service names and banners to open-port results."""
    for result in results:
        if result["state"] != "open":
            continue

        service, banner = identify_service(ip, result["port"], timeout)
        result["service"] = service
        result["banner"] = banner


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
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                error_code = sock.connect_ex((ip, port))

            if error_code == 0:
                return make_result(port, "open", "connection succeeded")

            if error_code == errno.ECONNREFUSED:
                return make_result(port, "closed", "connection refused")

            if error_code in TRANSIENT_LOCAL_ERRORS:
                last_error = error_code
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

            if error_code == errno.ETIMEDOUT:
                return make_result(port, "filtered", "timeout")

            # Errors such as host/network unreachable or permission denied mean
            # a connection could not be established, but not that the port was
            # actively confirmed closed.
            try:
                reason = os.strerror(error_code)
            except ValueError:
                reason = "socket error {}".format(error_code)
            return make_result(port, "filtered", reason)

        except socket.timeout:
            if attempt < retries:
                continue
            return make_result(port, "filtered", "timeout")
        except OSError as exc:
            last_error = exc.errno
            if exc.errno in TRANSIENT_LOCAL_ERRORS and attempt < retries:
                time.sleep(0.02 * (attempt + 1))
                continue
            state = "error" if exc.errno in TRANSIENT_LOCAL_ERRORS else "filtered"
            return make_result(port, state, str(exc))

    return make_result(port, "error", "probe failed: {}".format(last_error))


def tcp_connect_scan(
    ip,
    ports,
    timeout=1.0,
    max_threads=100,
    retries=1,
    progress=True,
):
    """Scan TCP ports concurrently using normal operating-system sockets."""
    results = []
    total = len(ports)

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        future_to_port = {
            pool.submit(_connect_probe, ip, port, timeout, retries): port
            for port in ports
        }

        for completed, future in enumerate(as_completed(future_to_port), start=1):
            port = future_to_port[future]

            try:
                results.append(future.result())
            except Exception as exc:
                results.append(
                    make_result(port, "error", "probe failed: {}".format(exc))
                )

            if progress and (completed % 50 == 0 or completed == total):
                print(
                    "\r  scanned {}/{} ports...".format(completed, total),
                    end="",
                    flush=True,
                )

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

    return "filtered", "unexpected response"


def build_syn_packets(ip, ports):
    """Create SYN packets with independently randomized source ports."""
    packets = []
    used_source_ports = set()

    for port in ports:
        source_port = random.randint(32768, 60999)
        while source_port in used_source_ports:
            source_port = random.randint(32768, 60999)
        used_source_ports.add(source_port)

        packets.append(
            IP(dst=ip)
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
    obtain a response.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "Scapy is not installed. Activate the virtual environment and run "
            "'pip install -r requirements.txt'."
        )

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError(
            "SYN scanning needs raw-socket privileges. Re-run with sudo, for "
            "example: sudo .venv/bin/python port_scanner.py TARGET --syn"
        )

    conf.verb = 0
    results_by_port = {}
    pending_ports = list(ports)
    total = len(ports)
    total_replies = 0

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

                # Any actual response is stronger evidence than an earlier
                # no-response result, so it replaces the pending status.
                results_by_port[port] = make_result(port, state, reason)

                if state == "open" and response.haslayer(TCP):
                    reset_packets.append(
                        IP(dst=ip)
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
    """Return exactly the rows the user requested for display/export."""
    if show_all:
        return list(results)
    return [result for result in results if result["state"] == "open"]


def summary_text(counts):
    parts = [
        "{} open".format(counts.get("open", 0)),
        "{} closed".format(counts.get("closed", 0)),
        "{} filtered".format(counts.get("filtered", 0)),
    ]
    if counts.get("error", 0):
        parts.append("{} error".format(counts["error"]))
    return ", ".join(parts)


def print_results(target, ip, results, elapsed, scan_type, show_all=False):
    displayed = select_results(results, show_all)
    counts = get_state_counts(results)

    print()
    print("=" * 76)
    print("  Scan report for {} ({})".format(target, ip))
    print("  Scan type : {}".format(scan_type))
    print("  Duration  : {:.2f}s".format(elapsed))
    print("  Summary   : {}".format(summary_text(counts)))
    print("=" * 76)

    if not displayed:
        if show_all:
            print("\n  No results were produced.\n")
        else:
            print("\n  No open ports found in the requested range.\n")
        return

    print("\n  {:<8}{:<11}{:<18}{}".format(
        "PORT", "STATE", "SERVICE", "BANNER / REASON"
    ))
    print("  {:<8}{:<11}{:<18}{}".format(
        "------", "--------", "---------------", "------------------------------------"
    ))

    # Iterate over 'displayed', never over the complete result list. This keeps
    # closed/filtered rows hidden unless --show-all was explicitly supplied.
    for result in displayed:
        detail = result["banner"] if result["state"] == "open" else result["reason"]
        if len(detail) > 64:
            detail = detail[:63] + "…"

        print("  {:<8}{:<11}{:<18}{}".format(
            result["port"],
            result["state"],
            result["service"],
            detail,
        ))

    if not show_all:
        print("\n  Showing open ports only. Use --show-all for every state.")
    print()


def write_report(path, target, ip, results, elapsed, scan_type, show_all=False):
    displayed = select_results(results, show_all)
    counts = get_state_counts(results)

    with open(path, "w", encoding="utf-8") as report:
        report.write("Port scan report\n")
        report.write("Target    : {} ({})\n".format(target, ip))
        report.write("Scan type : {}\n".format(scan_type))
        report.write(
            "Date      : {}\n".format(
                datetime.now().astimezone().isoformat(timespec="seconds")
            )
        )
        report.write("Duration  : {:.2f}s\n".format(elapsed))
        report.write("Summary   : {}\n\n".format(summary_text(counts)))
        report.write("{:<8}{:<11}{:<18}{}\n".format(
            "PORT", "STATE", "SERVICE", "BANNER / REASON"
        ))

        for result in displayed:
            detail = result["banner"] if result["state"] == "open" else result["reason"]
            report.write("{:<8}{:<11}{:<18}{}\n".format(
                result["port"],
                result["state"],
                result["service"],
                detail,
            ))


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------


EPILOG = """Examples:
  python3 port_scanner.py 192.168.1.10 -p 1-1024
  python3 port_scanner.py example.com -p 22,80,443 --show-all
  python3 port_scanner.py 192.168.1.10 -o report.txt
  sudo .venv/bin/python port_scanner.py 192.168.1.10 --syn --no-banner
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


def build_parser():
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description=(
            "TCP port scanner with multithreaded connect scanning and "
            "rate-controlled batched SYN scanning. Only scan authorized targets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )

    parser.add_argument("target", help="Target IPv4 address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports such as '22,80,443' or '1-1024' (default: 1-1024)",
    )
    parser.add_argument(
        "-t", "--timeout", type=positive_float, default=1.0,
        help="Per-connection/per-batch timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--threads", type=positive_int, default=100,
        help="Connect-scan worker threads (default: 100)",
    )
    parser.add_argument(
        "--syn", action="store_true",
        help="Use rate-controlled half-open SYN scanning through Scapy",
    )
    parser.add_argument(
        "--batch-size", type=positive_int, default=512,
        help="Initial SYN packets per batch (default: 512)",
    )
    parser.add_argument(
        "--inter", type=non_negative_float, default=0.001,
        help="Delay between SYN packets in seconds (default: 0.001)",
    )
    parser.add_argument(
        "--retries", type=non_negative_int, default=1,
        help="Retry unanswered/transient probes this many times (default: 1)",
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="Skip service and banner identification",
    )
    parser.add_argument(
        "--show-all", action="store_true",
        help="Display and export closed, filtered, and error states too",
    )
    parser.add_argument(
        "--no-progress", action="store_true",
        help="Disable the live progress display",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write a plain-text report to FILE",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        ip = resolve_target(args.target)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    print("\nTarget: {} ({})".format(args.target, ip))
    print("Ports : {}".format(len(ports)))
    print("Mode  : {}\n".format(
        "SYN scan (Scapy, batched)" if args.syn else "TCP connect scan (socket)"
    ))

    started = time.perf_counter()

    try:
        if args.syn:
            results = syn_scan(
                ip,
                ports,
                timeout=args.timeout,
                batch_size=args.batch_size,
                retries=args.retries,
                inter=args.inter,
                progress=not args.no_progress,
            )
            scan_type = "SYN scan (Scapy, batched)"
        else:
            results = tcp_connect_scan(
                ip,
                ports,
                timeout=args.timeout,
                max_threads=args.threads,
                retries=args.retries,
                progress=not args.no_progress,
            )
            scan_type = "TCP connect scan (socket)"
    except (RuntimeError, PermissionError, OSError) as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        return 1

    if not args.no_banner:
        identify_open_services(ip, results, args.timeout)

    elapsed = time.perf_counter() - started

    print_results(
        args.target,
        ip,
        results,
        elapsed,
        scan_type,
        show_all=args.show_all,
    )

    if args.output:
        try:
            write_report(
                args.output,
                args.target,
                ip,
                results,
                elapsed,
                scan_type,
                show_all=args.show_all,
            )
            print("Report written to {}".format(args.output))
        except OSError as exc:
            print("Error writing report: {}".format(exc), file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
