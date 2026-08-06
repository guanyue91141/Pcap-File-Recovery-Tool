"""Unit tests for the untrusted-filename sanitizer."""

import pytest

from pcap_file_recovery.recovery import sanitize_filename


@pytest.mark.parametrize(
    ("hostile", "expected"),
    [
        ("../../../../etc/cron.d/evil", "evil"),
        ("..\\..\\boom.bat", "boom.bat"),
        ("/etc/passwd", "passwd"),
        ("C:\\Windows\\system32\\drivers\\etc\\hosts", "hosts"),
        ("..\x00/..\x00/shadow", "shadow"),
    ],
)
def test_path_traversal_is_stripped(hostile: str, expected: str) -> None:
    assert sanitize_filename(hostile) == expected


@pytest.mark.parametrize("hostile", ["", ".", "..", "...", "/", "////", "\x00"])
def test_degenerate_names_become_unnamed(hostile: str) -> None:
    assert sanitize_filename(hostile) == "unnamed"


def test_hidden_files_are_unhidden() -> None:
    assert sanitize_filename(".bashrc") == "bashrc"


def test_control_and_special_characters_are_neutralized() -> None:
    result = sanitize_filename("re\x1b[31mport;$(rm -rf ~).pdf")
    assert all(ch.isprintable() for ch in result)
    for forbidden in ("\x1b", ";", "$", "(", ")", "~", " "):
        assert forbidden not in result
    assert result.endswith(".pdf")


def test_long_names_are_truncated_but_keep_extension() -> None:
    result = sanitize_filename("A" * 500 + ".png")
    assert len(result) <= 120
    assert result.endswith(".png")


def test_benign_names_pass_through() -> None:
    assert sanitize_filename("invoice_2024-06.v1.pdf") == "invoice_2024-06.v1.pdf"
