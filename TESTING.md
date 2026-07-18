# Testing

Install the package and development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the complete suite:

```bash
python -m pytest tests -v
```

Run coverage enforcement:

```bash
python -m pytest tests \
  --cov=portscanner \
  --cov-report=term-missing \
  --cov-fail-under=75
```

The suite is network-free unless a test explicitly starts a local loopback
service. Sockets, Scapy responses, TLS sessions, interruptions, target
resolution, CIDR expansion, target files, and report writers are mocked or
constructed locally.

Important v5.0 coverage areas include:

- IPv4 and IPv6 target resolution.
- Multiple positional targets and target files.
- IPv4/IPv6 CIDR expansion and edge prefixes.
- Target deduplication.
- Target and probe safety limits.
- Connect and SYN scan classification.
- HTTP, TLS, certificate, and banner identification.
- Scan profiles and explicit overrides.
- Single-target and multi-target text/JSON/CSV reports.
- Graceful Ctrl+C preservation.
- Installed console, module, and legacy entry points.

The v5.0 release suite contains 168 tests.
