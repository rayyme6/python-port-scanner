"""Compatibility module for code that imports :mod:`port_scanner`."""

import sys

from portscanner import cli as _implementation


if __name__ == "__main__":
    _implementation.console_main()
else:
    sys.modules[__name__] = _implementation
