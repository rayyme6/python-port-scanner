"""Allow ``python -m portscanner`` to behave like the ``portscan`` command."""

import sys

from .cli import console_main


if __name__ == "__main__":
    sys.argv[0] = "portscan"
    console_main()
