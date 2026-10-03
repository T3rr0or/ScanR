import pytest

from scanr.core import evidence


@pytest.mark.parametrize("data,expected", [
    (b"\x89PNG\r\n\x1a\nrest", "image/png"),
    (b"\xff\xd8\xff\xe0JFIF", "image/jpeg"),
    (b"GIF89a....", "image/gif"),
    (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"),
    (b"%PDF-1.4", "application/pdf"),
    (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "text/plain"),
    ("Résumé ünïcode".encode() * 1000, "text/plain"),
    (b"<svg onload=alert(1)>", "text/plain"),
    (b"\x1b[31m[+] nmap done\x1b[0m\n", "text/plain"),
])
def test_detect(data, expected):
    assert evidence.detect_type(data) == expected


@pytest.mark.parametrize("data", [b"MZ\x90\x00", b"PK\x03\x04", b"\x7fELF\x02\x01", b"\xff\xfe\x00\x00binary"])
def test_rejects_binaries(data):
    with pytest.raises(evidence.EvidenceError):
        evidence.detect_type(data)


def test_text_cut_mid_character_is_still_text():
    data = b"a" + ("é" * 5000).encode()  # byte 8192 falls inside a two-byte character
    assert evidence.detect_type(data) == "text/plain"


def test_paths_stay_inside_the_root(tmp_path, monkeypatch):
    from scanr.config import get_settings

    monkeypatch.setattr(get_settings(), "evidence_dir", tmp_path)
    with pytest.raises(evidence.EvidenceError):
        evidence.path_for("..", "..")
