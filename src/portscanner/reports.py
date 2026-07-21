"""portscanner.reports — result formatting and text/JSON/CSV report writers.

Pure presentation layer: everything here consumes the plain result dicts
produced by ``make_result`` and either prints them or serializes them to
disk. Nothing in this module opens a socket.
"""

import csv
import json
import os
from collections import Counter

from .net import address_family_name
from .scan_result import SCANNER_NAME, SCANNER_VERSION

REPORT_FORMATS = ("auto", "text", "json", "csv")

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
