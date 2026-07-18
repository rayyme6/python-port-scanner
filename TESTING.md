# Testing

Install the development dependencies inside the project virtual environment:

```bash
python3 -m pip install -r requirements-dev.txt
```

Run the complete test suite:

```bash
python3 -m pytest -v
```

Run it with coverage:

```bash
python3 -m pytest \
  --cov=port_scanner \
  --cov-report=term-missing \
  --cov-fail-under=75
```

The tests do not scan external hosts and do not require root privileges. Socket
outcomes and packet responses are simulated or constructed locally. The Scapy
tests create packet objects but do not transmit them.
