"""Command-line interface for the PCAP file recovery tool."""

import argparse
import os

from pcap_file_recovery import __version__
from pcap_file_recovery.recovery import FileRecoveryTool

DEFAULT_PCAP = "capture.pcapng"
DEFAULT_OUTPUT_DIR = "recovered_files"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcap-file-recovery",
        description="Recover files transferred or exfiltrated over the network from a PCAP capture.",
    )
    parser.add_argument(
        "pcap_file",
        nargs="?",
        default=DEFAULT_PCAP,
        help=f"packet capture to analyze (default: {DEFAULT_PCAP})",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"directory for recovered files (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``pcap-file-recovery`` console script."""
    args = build_parser().parse_args(argv)

    if not os.path.exists(args.pcap_file):
        print(f"Error: {args.pcap_file} not found!")
        print("Pass the path to a capture file, e.g.: pcap-file-recovery capture.pcapng")
        return 1

    recovery_tool = FileRecoveryTool(args.pcap_file, output_dir=args.output_dir)
    return 0 if recovery_tool.analyze_traffic() else 1
