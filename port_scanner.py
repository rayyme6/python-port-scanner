#!/usr/bin/env python3
"""Backward-compatible launcher for the installable ``portscanner`` package.

Existing commands such as ``python3 port_scanner.py TARGET`` remain supported.
New installations should normally use ``portscan TARGET`` or
``python -m portscanner TARGET``.
"""

from pathlib import Path
import sys


# Running this file directly from a source checkout should work before the
# project has been installed. Editable/wheel installations do not need this.
_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from portscanner import cli as _implementation  # noqa: E402


if __name__ == "__main__":
    _implementation.console_main()
else:
    # Preserve ``import port_scanner`` as an alias of the real implementation.
    # This also keeps monkeypatching and older integrations working correctly.
    sys.modules[__name__] = _implementation