"""Allow running the tool as ``python -m pcap_file_recovery``."""

from pcap_file_recovery.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
