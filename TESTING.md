# Testing

Install development dependencies inside a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

Run the complete suite:

```bash
python -m pytest tests -v
```

Run coverage enforcement:

```bash
python -m pytest tests \
  --cov=port_scanner \
  --cov-report=term-missing \
  --cov-fail-under=75
```

The v4.5 suite contains **130 tests** and currently reaches approximately
**86% statement coverage**. Tests are network-free: sockets, TLS sessions,
Scapy responses, thread-pool futures, Ctrl+C interruptions, and report writers
are mocked or constructed locally.

Interruption tests verify that completed connect results, classified SYN
responses, and completed service banners survive Ctrl+C; partial text, JSON,
and CSV reports carry explicit interruption and progress metadata; and the CLI
returns exit status 130.