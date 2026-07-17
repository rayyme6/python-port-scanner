#!/usr/bin/env python3
"""
port_scanner.py — TCP port scanner with service identification.

Two scan engines:
  * connect  — full TCP three-way handshake via the socket library.
               No special privileges required. Reliable, a bit noisier.
  * syn      — half-open SYN scan via Scapy. Faster and stealthier,
               but requires root/administrator privileges (raw sockets).

Legal note: only scan hosts and networks you own or are explicitly
authorized to test. Scanning systems without permission is illegal in
most jurisdictions (e.g. it can violate the U.S. Computer Fraud and
Abuse Act) even when no exploitation takes place.

Examples:
    python3 port_scanner.py 192.168.1.10 -p 1-1024
    python3 port_scanner.py scanme.example.com -p 22,80,443 -o report.txt
    sudo python3 port_scanner.py 192.168.1.10 -p 1-65535 --syn
"""

import argparse
import errno
import os
import random
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    from scapy.all import sr1, send, IP, TCP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Well-known ports, used as a fallback label when a live banner can't be read.
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

# --------------------------------------------------------------------------
# Port spec parsing
# --------------------------------------------------------------------------

def parse_ports(port_str):
    """Parse '22,80,443' / '1-1000' / '1-100,443,8000-8100' into a sorted list of ints."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"invalid port range '{part}'")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"invalid port '{part}'")
            ports.add(p)
    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: could not resolve host '{target}'")
        sys.exit(1)


# --------------------------------------------------------------------------
# Service / banner identification
# --------------------------------------------------------------------------

def identify_service(ip, port, timeout):
    """
    Best-effort service fingerprint for an already-known-open port.

    Strategy: many services (SSH, FTP, SMTP) volunteer a banner the instant
    you connect, so listen passively first. If nothing arrives, actively
    probe with a generic HTTP request — HTTP turns up on all kinds of
    nonstandard ports (dev servers, admin panels, proxies). The port-number
    table is only used as a last-resort label.
    """
    service = COMMON_PORTS.get(port, "unknown")
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            s.settimeout(min(timeout, 0.8))
            try:
                data = s.recv(1024)
            except socket.timeout:
                data = b""

            if not data:
                try:
                    s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    s.settimeout(timeout)
                    data = s.recv(1024)
                except socket.error:
                    data = b""

            text = data.decode(errors="ignore").strip()

            if text.lower().startswith("http/"):
                service = "HTTP"
                server_line = next(
                    (l for l in text.split("\r\n") if l.lower().startswith("server:")),
                    None,
                )
                banner = server_line.split(":", 1)[1].strip() if server_line else text.split("\r\n")[0]
            elif text.upper().startswith("SSH-"):
                service = "SSH"
                banner = text.split("\n")[0][:120]
            elif text:
                banner = text.split("\n")[0][:120]
    except Exception:
        pass

    return service, banner


# --------------------------------------------------------------------------
# Engine 1: TCP connect scan (socket library)
# --------------------------------------------------------------------------

def _connect_probe(ip, port, timeout):
    """
    Probe one port. Returns (is_open, got_reply):
      got_reply is True if the host actively responded — either the port is
      open, or it sent back an explicit "connection refused". It's False if
      the probe just timed out with no response at all, which usually means
      something other than "closed port" (host down, wrong IP, or traffic
      being silently dropped somewhere in the path).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            err = sock.connect_ex((ip, port))
            if err == 0:
                return True, True
            if err == errno.ECONNREFUSED:
                return False, True
            return False, False
    except socket.error:
        return False, False


def tcp_connect_scan(ip, ports, timeout=1.0, max_threads=200, grab_banners=True, progress=True):
    open_ports = []
    replied = 0
    total = len(ports)
    done = 0

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_connect_probe, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            done += 1
            if progress and (done % 50 == 0 or done == total):
                print(f"\r  scanned {done}/{total} ports...", end="", flush=True)
            is_open, got_reply = future.result()
            if got_reply:
                replied += 1
            if is_open:
                open_ports.append(futures[future])

    if progress:
        print(f"\r  scanned {total}/{total} ports.{' ' * 15}")

    if total and replied == 0:
        print(f"  Note: all {total} probes timed out with zero replies (not even a "
              f"'refused') — that pattern usually means {ip} is down, not actually at "
              f"that address anymore, or something is silently dropping the traffic, "
              f"rather than the host genuinely having no open ports. Try `ping {ip}` "
              f"to sanity-check it's reachable before trusting this result.")

    results = []
    for port in sorted(open_ports):
        service, banner = (identify_service(ip, port, timeout) if grab_banners
                            else (COMMON_PORTS.get(port, "unknown"), ""))
        results.append({"port": port, "state": "open", "service": service, "banner": banner})
    return results


# --------------------------------------------------------------------------
# Engine 2: SYN scan (Scapy, half-open) — requires raw sockets / root
# --------------------------------------------------------------------------

def _syn_probe(ip, port, timeout, sport):
    """Returns (is_open, got_reply) — see _connect_probe for what got_reply means."""
    pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags="S", seq=random.randint(0, 2**32 - 1))
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return False, False  # no reply at all: filtered, host down, or silently dropped

    if resp.haslayer(TCP):
        tcp = resp.getlayer(TCP)
        if tcp.flags == "SA":  # SYN-ACK -> open
            rst = IP(dst=ip) / TCP(sport=sport, dport=port, flags="R", seq=tcp.ack)
            send(rst, verbose=0)
            return True, True
        return False, True  # RST/RA -> closed, but the host is definitely alive
    if resp.haslayer(ICMP):
        return False, True  # something in the path actively responded
    return False, False


def syn_scan(ip, ports, timeout=1.0, grab_banners=True, progress=True):
    if not SCAPY_AVAILABLE:
        print("Error: Scapy is not installed for this Python interpreter.")
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            print("You're running as root (via sudo). If you already ran 'pip install scapy'")
            print("as your normal user, root can't see it — that installed scapy into *your*")
            print("user site-packages, which is a different location from root's.")
            print("Fix:   sudo pip install scapy")
            print("(If that errors with 'externally-managed-environment', add --break-system-packages.)")
        else:
            print("Install it with: pip install scapy")
        sys.exit(1)

    conf.verb = 0
    sport = random.randint(1025, 65500)
    open_ports = []
    replied = 0
    total = len(ports)

    try:
        for i, port in enumerate(ports, 1):
            if progress and (i % 20 == 0 or i == total):
                print(f"\r  scanned {i}/{total} ports...", end="", flush=True)
            is_open, got_reply = _syn_probe(ip, port, timeout, sport)
            if got_reply:
                replied += 1
            if is_open:
                open_ports.append(port)
    except PermissionError:
        print("\nError: SYN scanning needs raw-socket access. Re-run with sudo/administrator privileges.")
        sys.exit(1)
    except OSError as e:
        print(f"\nError: {e} (SYN scanning needs raw-socket access — try sudo).")
        sys.exit(1)

    if progress:
        print(f"\r  scanned {total}/{total} ports.{' ' * 15}")

    if total and replied == 0:
        print(f"  Note: all {total} probes timed out with zero replies (not even a "
              f"RST) — that pattern usually means {ip} is down, not actually at that "
              f"address anymore, or something is silently dropping the traffic, rather "
              f"than the host genuinely having no open ports. Try `ping {ip}` to "
              f"sanity-check it's reachable before trusting this result.")

    results = []
    for port in sorted(open_ports):
        service, banner = (identify_service(ip, port, timeout) if grab_banners
                            else (COMMON_PORTS.get(port, "unknown"), ""))
        results.append({"port": port, "state": "open", "service": service, "banner": banner})
    return results


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def print_results(target, ip, open_ports, elapsed, scan_type):
    print()
    print("=" * 62)
    print(f"  Scan report for {target} ({ip})")
    print(f"  Scan type : {scan_type}")
    print(f"  Duration  : {elapsed:.2f}s")
    print("=" * 62)

    if not open_ports:
        print("\n  No open ports found in the given range.\n")
        return

    print(f"\n  {'PORT':<8}{'STATE':<8}{'SERVICE':<16}{'BANNER'}")
    print(f"  {'-'*6:<8}{'-'*5:<8}{'-'*7:<16}{'-'*30}")
    for r in open_ports:
        banner = r["banner"][:48] + ("…" if len(r["banner"]) > 48 else "")
        print(f"  {r['port']:<8}{r['state']:<8}{r['service']:<16}{banner}")
    print(f"\n  {len(open_ports)} open port(s) found.\n")


def write_report(path, target, ip, open_ports, elapsed, scan_type):
    with open(path, "w") as f:
        f.write(f"Port scan report\n")
        f.write(f"Target    : {target} ({ip})\n")
        f.write(f"Scan type : {scan_type}\n")
        f.write(f"Date      : {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"Duration  : {elapsed:.2f}s\n\n")
        if not open_ports:
            f.write("No open ports found.\n")
            return
        f.write(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<16}{'BANNER'}\n")
        for r in open_ports:
            f.write(f"{r['port']:<8}{r['state']:<8}{r['service']:<16}{r['banner']}\n")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

EPILOG = """Examples:
    python3 port_scanner.py 192.168.1.10 -p 1-1024
    python3 port_scanner.py scanme.example.com -p 22,80,443 -o report.txt
    sudo python3 port_scanner.py 192.168.1.10 -p 1-65535 --syn
"""


def main():
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description="TCP port scanner with service identification. "
                     "Only scan hosts you own or are authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Ports to scan: '22,80,443' or '1-1000' (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                         help="Per-port timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=200,
                         help="Max concurrent threads for connect scan (default: 200)")
    parser.add_argument("--syn", action="store_true",
                         help="Use a SYN (half-open) scan via Scapy instead of a full TCP connect scan. Needs root.")
    parser.add_argument("--no-banner", action="store_true",
                         help="Skip service/banner identification on open ports (faster)")
    parser.add_argument("-o", "--output", metavar="FILE",
                         help="Write a plain-text report to FILE")
    args = parser.parse_args()

    ip = resolve_target(args.target)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"\nTarget: {args.target} ({ip})")
    print(f"Ports : {len(ports)}")
    print(f"Mode  : {'SYN scan (scapy)' if args.syn else 'TCP connect scan (socket)'}\n")

    start = time.time()
    if args.syn:
        open_ports = syn_scan(ip, ports, timeout=args.timeout, grab_banners=not args.no_banner)
        scan_type = "SYN scan (Scapy)"
    else:
        open_ports = tcp_connect_scan(ip, ports, timeout=args.timeout, max_threads=args.threads,
                                       grab_banners=not args.no_banner)
        scan_type = "TCP connect scan (socket)"
    elapsed = time.time() - start

    print_results(args.target, ip, open_ports, elapsed, scan_type)

    if args.output:
        write_report(args.output, args.target, ip, open_ports, elapsed, scan_type)
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    if sys.platform not in ("linux", "darwin") and "--syn" in sys.argv:
        print("Note: SYN scanning is only supported on Linux/macOS in this script.")
    main()
