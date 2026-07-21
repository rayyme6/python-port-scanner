#!/usr/bin/env python3
"""
portscanner.cli — command-line entry point and scan orchestration.

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

This module is orchestration only: argument parsing, profile resolution, and
wiring one target's worth of scanning + service ID + reporting together. The
actual engines live in sibling modules and are re-exported below so existing
code (and ``python3 port_scanner.py``) keeps working unchanged:

  * portscanner.net          — target/port/address parsing and resolution
  * portscanner.scan_result  — the shared result dict and ScanInterrupted
  * portscanner.connect_scan — the TCP connect scan engine
  * portscanner.synscan      — the Scapy-based SYN scan engine
  * portscanner.service_id   — banner grabbing and HTTP/TLS identification
  * portscanner.reports      — text/JSON/CSV report writers
"""

import argparse
import os
import sys
import time
from datetime import datetime

from . import __version__

from .net import (
    parse_ports,
    strip_address_brackets,
    address_family,
    address_family_name,
    socket_endpoint,
    resolve_target,
    chunked,
    read_target_file,
    network_host_count,
    parse_network_spec,
    collect_targets,
    validate_probe_plan,
    is_ip_literal,
    DEFAULT_MAX_TARGETS,
    DEFAULT_MAX_PROBES,
)
from .scan_result import ScanInterrupted, make_result, COMMON_PORTS
from .connect_scan import (
    tcp_connect_scan,
    _connect_probe,
    _connect_future_result,
    TRANSIENT_LOCAL_ERRORS,
    AMBIGUOUS_CONNECT_ERRORS,
)
from .synscan import (
    syn_scan,
    classify_syn_response,
    network_layer,
    build_syn_packets,
    load_scapy,
    IP,
    IPv6,
    TCP,
    ICMP,
    conf,
    send,
    sr,
    ICMPV6_ERROR_LAYERS,
    SCAPY_AVAILABLE,
    SCAPY_IMPORT_ATTEMPTED,
    SCAPY_IMPORT_ERROR,
    SCAPY_IMPORT_DIAGNOSTICS,
)
from .service_id import (
    strip_telnet_negotiation,
    readable_banner,
    http_host_header,
    build_http_request,
    receive_response,
    http_response_banner,
    certificate_name_value,
    normalize_dns_name,
    dns_pattern_matches,
    certificate_matches_hostname,
    decode_certificate,
    probe_tls,
    identify_service,
    _service_future_result,
    identify_open_services,
    HTTP_PROBE_PORTS,
    TLS_PROBE_PORTS,
    HTTPS_PROBE_PORTS,
)
from .reports import (
    get_state_counts,
    select_results,
    select_report_results,
    summary_dict,
    summary_text,
    result_detail,
    normalized_result,
    resolve_output_format,
    report_progress,
    build_report_document,
    print_results,
    write_text_report,
    write_json_report,
    write_csv_report,
    write_report,
    aggregate_state_counts,
    build_batch_report_document,
    write_batch_json_report,
    write_batch_text_report,
    write_batch_csv_report,
    write_batch_report,
    print_batch_summary,
    DEFAULT_PROFILE,
    REPORT_FORMATS,
    PROFILE_SETTING_NAMES,
    SCAN_PROFILES,
    normalized_scan_settings,
)
from .scan_result import SCANNER_NAME, SCANNER_VERSION


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
