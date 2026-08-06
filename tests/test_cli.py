"""CLI entry point tests."""

import subprocess
import sys

import pytest

from conftest import build_pcap, http_response_frame
from pcap_file_recovery.cli import main


def test_help_exits_zero():
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0


def test_missing_pcap_returns_error_code(tmp_path):
    assert main([str(tmp_path / "nope.pcapng")]) == 1


def test_end_to_end_run(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(build_pcap([http_response_frame("flag.txt", b"CTF{synthetic}")]))
    out_dir = tmp_path / "out"

    assert main([str(pcap), "-o", str(out_dir)]) == 0
    assert (out_dir / "flag.txt").read_bytes() == b"CTF{synthetic}"
    assert (out_dir / "recovery_summary.txt").exists()


def test_module_invocation_help():
    result = subprocess.run(
        [sys.executable, "-m", "pcap_file_recovery", "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0
    assert "pcap-file-recovery" in result.stdout
