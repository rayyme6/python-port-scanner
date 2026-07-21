"""portscanner.synscan — rate-controlled half-open SYN scanning via Scapy.

Requires raw-socket privileges (normally sudo on Linux). Scapy is imported
lazily on first use — ``load_scapy()`` populates the module-level ``TCP``,
``ICMP``, ``IP``, ``IPv6``, ``conf``, ``send``, and ``sr`` names so the rest
of this module, and tests, can patch or read them directly.
"""

import io
import os
import random
import socket
from contextlib import redirect_stderr

from .net import address_family, chunked, strip_address_brackets
from .scan_result import ScanInterrupted, make_result

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
