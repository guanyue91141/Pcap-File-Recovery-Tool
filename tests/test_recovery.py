"""Integration tests: synthetic captures in, carved files out.

Every capture is built in code (see conftest.py) so the exact hostile bytes
under test are visible in the test itself.
"""

import struct

from conftest import (
    build_pcap,
    dns_query_frame,
    http_response_frame,
    icmp_frame,
    pcap_global_header,
    pcap_record,
    tcp_frame,
)

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"A" * 32 + b"IEND\xaeB`\x82"
PDF_BODY = b"%PDF-1.4 synthetic body for testing %%EOF"


# --- happy path -----------------------------------------------------------


def test_http_response_carve_happy_path(run_tool):
    tool, out_dir, ok = run_tool(build_pcap([http_response_frame("report.pdf", PDF_BODY)]))
    assert ok
    assert (out_dir / "report.pdf").read_bytes() == PDF_BODY
    assert any(f["source"] == "HTTP Response" for f in tool.recovered_files)


def test_png_carved_from_split_tcp_stream(run_tool):
    half = len(PNG_BYTES) // 2
    frames = [
        tcp_frame(PNG_BYTES[:half], sport=4444, dport=5555),
        tcp_frame(PNG_BYTES[half:], sport=4444, dport=5555),
    ]
    tool, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    carved = [p.read_bytes() for p in out_dir.iterdir()]
    assert PNG_BYTES in carved  # reassembled across packets, not per-packet


def test_dns_exfiltration_hex_labels_decoded(run_tool):
    _, out_dir, ok = run_tool(build_pcap([dns_query_frame("48656c6c6f.attacker.example.")]))
    assert ok
    assert (out_dir / "dns_exfiltrated_data.bin").read_bytes() == b"Hello"


def test_icmp_covert_channel_payload_carved(run_tool):
    payload = b"SECRET-EXFIL-DATA"
    _, out_dir, ok = run_tool(build_pcap([icmp_frame(payload)]))
    assert ok
    assert (out_dir / "icmp_hidden_data.bin").read_bytes() == payload


def test_smtp_base64_attachment_decoded(run_tool):
    # Regression test: base64 was never imported in the original script, so
    # this path always died with a silently-swallowed NameError.
    smtp_payload = (
        b"Content-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="invoice.pdf"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"JVBERi0xLjQ=\r\n"
        b"--boundary--\r\n"
    )
    _, out_dir, ok = run_tool(build_pcap([tcp_frame(smtp_payload, sport=4321, dport=25)]))
    assert ok
    assert (out_dir / "invoice.pdf").read_bytes() == b"%PDF-1.4"


def test_ftp_data_stream_reassembled(run_tool):
    frames = [
        tcp_frame(b"chunk-one|", sport=20, dport=6000),
        tcp_frame(b"chunk-two", sport=20, dport=6000),
    ]
    _, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    assert (out_dir / "ftp_transfer_0.bin").read_bytes() == b"chunk-one|chunk-two"


# --- hostile filenames ----------------------------------------------------


def test_http_filename_path_traversal_is_contained(run_tool, tmp_path):
    hostile = "../../../pwned.txt"
    _, out_dir, ok = run_tool(build_pcap([http_response_frame(hostile, b"owned")]))
    assert ok
    # Nothing may escape the output directory...
    assert not (tmp_path / "pwned.txt").exists()
    assert not (tmp_path.parent / "pwned.txt").exists()
    # ...but the payload is still recovered, under a sanitized name.
    assert (out_dir / "pwned.txt").read_bytes() == b"owned"


def test_absolute_path_filename_is_contained(run_tool, tmp_path):
    _, out_dir, ok = run_tool(build_pcap([http_response_frame("/etc/passwd", b"root:x:0:0")]))
    assert ok
    assert (out_dir / "passwd").read_bytes() == b"root:x:0:0"
    # Only the input capture and the output directory may exist at the top level.
    assert {p.name for p in tmp_path.iterdir()} == {"capture.pcap", "recovered"}


def test_duplicate_filenames_do_not_clobber_earlier_carves(run_tool):
    frames = [
        http_response_frame("dup.txt", b"first", dport=40001),
        http_response_frame("dup.txt", b"second", dport=40002),
    ]
    _, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    contents = {(out_dir / "dup.txt").read_bytes(), (out_dir / "dup_1.txt").read_bytes()}
    assert contents == {b"first", b"second"}


def test_ftp_stor_filename_control_chars_not_echoed(run_tool, capsys):
    payload = b"STOR \x1b]0;pwned\x07innocent.txt\r\n"
    _, _, ok = run_tool(build_pcap([tcp_frame(payload, sport=4321, dport=21)]))
    assert ok
    out = capsys.readouterr().out
    assert "Found FTP upload:" in out
    assert "\x1b" not in out and "\x07" not in out


# --- malformed and truncated captures -------------------------------------


def test_empty_capture_reports_nothing(run_tool):
    tool, out_dir, ok = run_tool(pcap_global_header())
    assert ok
    assert tool.recovered_files == []
    assert list(out_dir.iterdir()) == []  # no summary, no stray files


def test_truncated_record_header_does_not_crash(run_tool):
    tool, _, ok = run_tool(pcap_global_header() + b"\x00" * 8)
    assert ok
    assert tool.recovered_files == []


def test_record_length_field_larger_than_data(run_tool):
    # incl_len claims 50 bytes, only 5 are present.
    blob = pcap_global_header() + struct.pack("<IIII", 0, 0, 50, 50) + b"short"
    tool, _, ok = run_tool(blob)
    assert ok
    assert tool.recovered_files == []


def test_huge_length_field_does_not_exhaust_memory(run_tool):
    # incl_len claims ~4GB; the file holds 4 bytes. Must not allocate 4GB.
    blob = pcap_global_header() + pcap_record(b"tiny", incl_len=0xFFFFFFF0, orig_len=0xFFFFFFF0)
    tool, _, ok = run_tool(blob)
    assert ok
    assert tool.recovered_files == []


def test_garbage_input_fails_cleanly(run_tool):
    tool, _, ok = run_tool(b"this is not a pcap file at all..........")
    assert ok is False
    assert tool.recovered_files == []


def test_truncated_global_header_fails_cleanly(run_tool):
    tool, _, ok = run_tool(pcap_global_header()[:12])
    assert ok is False
    assert tool.recovered_files == []


def test_non_utf8_dns_qname_does_not_crash(run_tool):
    _, _, ok = run_tool(build_pcap([dns_query_frame(b"\xff\xfe\xfd.example.")]))
    assert ok


def test_odd_length_hex_dns_label_is_skipped(run_tool):
    _, out_dir, ok = run_tool(build_pcap([dns_query_frame("48656c6c6.example.")]))
    assert ok
    assert not (out_dir / "dns_exfiltrated_data.bin").exists()


# --- resource exhaustion --------------------------------------------------


def test_max_files_cap_stops_carve_bomb(run_tool):
    frames = [http_response_frame(f"file{i}.txt", b"x" * 8, dport=41000 + i) for i in range(5)]
    tool, out_dir, ok = run_tool(build_pcap(frames), max_files=2)
    assert ok
    assert len(tool.recovered_files) == 2
    carved = [p for p in out_dir.iterdir() if p.name != "recovery_summary.txt"]
    assert len(carved) == 2


def test_signature_carve_is_size_capped(run_tool):
    # A PDF header with no %%EOF trailer must be capped, not carved unbounded.
    big = b"%PDF-1.7 " + b"B" * 4096
    tool, out_dir, ok = run_tool(build_pcap([tcp_frame(big, sport=4444, dport=5555)]))
    assert ok
    for f in tool.recovered_files:
        assert f["size"] <= tool.max_carve_size
