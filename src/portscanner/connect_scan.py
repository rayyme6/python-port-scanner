"""portscanner.connect_scan — multithreaded full TCP connect scanning.

No special privileges required: this engine completes a real three-way
handshake per port using ordinary Python sockets, spread across a thread
pool. It is slower and noisier than the SYN engine but works everywhere.
"""

import errno
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .net import address_family, socket_endpoint
from .scan_result import ScanInterrupted, make_result


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
