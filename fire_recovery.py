#!/usr/bin/env python3
"""Backwards-compatible entry point.

The tool now lives in the ``pcap_file_recovery`` package under ``src/``.
Install the project (``pip install -e .``) and run ``pcap-file-recovery``
or ``python -m pcap_file_recovery``; this shim keeps the old
``python fire_recovery.py`` invocation working.
"""

from pcap_file_recovery.cli import main
from pcap_file_recovery.recovery import FileRecoveryTool as FileRecoveryTool  # re-export

if __name__ == "__main__":
    raise SystemExit(main())
