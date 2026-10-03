"""Evidence attachments: upload, typing, serving, permissions and cleanup."""
import uuid
import zlib
import struct

import pytest


def tiny_png() -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"\x00\xff\x00\x00"  # one red pixel
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


@pytest.fixture(autouse=True)
def evidence_dir(tmp_path, monkeypatch):
    from scanr.config import get_settings

    monkeypatch.setattr(get_settings(), "evidence_dir", tmp_path / "evidence")
    return tmp_path / "evidence"


async def _finding(client, headers):
    scan_id = (await client.post("/api/v1/scans", json={"name": "ev", "targets": ["198.51.100.40"]}, headers=headers)).json()["id"]
    fid = (await client.post(f"/api/v1/scans/{scan_id}/findings/manual", headers=headers,
                             json={"title": f"Ev {uuid.uuid4().hex[:6]}", "description": "d"})).json()["id"]
    return scan_id, fid


async def _upload(client, headers, fid, content, name="shot.png", caption=""):
    return await client.post(f"/api/v1/findings/{fid}/attachments", headers=headers,
                             files={"file": (name, content, "application/octet-stream")}, data={"caption": caption})


@pytest.mark.asyncio
async def test_upload_list_download_caption_delete(client, auth_headers, evidence_dir):
    _, fid = await _finding(client, auth_headers)
    r = await _upload(client, auth_headers, fid, tiny_png(), name="../../etc/passwd.png", caption="Login bypass")
    assert r.status_code == 201, r.text
    att = r.json()
    assert att["content_type"] == "image/png" and att["caption"] == "Login bypass"
    assert "/" not in att["filename"] and att["uploaded_by"] == "admin@scanr.local" and len(att["sha256"]) == 64
    stored = evidence_dir / fid / att["id"]
    assert stored.read_bytes() == tiny_png()

    listed = (await client.get(f"/api/v1/findings/{fid}/attachments", headers=auth_headers)).json()
    assert [a["id"] for a in listed] == [att["id"]]

    content = await client.get(f"/api/v1/attachments/{att['id']}/content", headers=auth_headers)
    assert content.status_code == 200 and content.content == tiny_png()
    assert content.headers["content-type"] == "image/png" and content.headers["x-content-type-options"] == "nosniff"
    assert content.headers["content-disposition"].startswith("inline")
    assert "default-src 'none'" in content.headers["content-security-policy"]

    upd = await client.patch(f"/api/v1/attachments/{att['id']}", json={"caption": "  "}, headers=auth_headers)
    assert upd.json()["caption"] is None
    assert (await client.delete(f"/api/v1/attachments/{att['id']}", headers=auth_headers)).status_code == 204
    assert not stored.exists()


@pytest.mark.asyncio
async def test_types_are_sniffed_not_trusted(client, auth_headers):
    _, fid = await _finding(client, auth_headers)
    html = b"<!doctype html><script>alert(document.domain)</script>"
    r = await _upload(client, auth_headers, fid, html, name="poc.html")
    assert r.status_code == 201 and r.json()["content_type"] == "text/plain"
    served = await client.get(f"/api/v1/attachments/{r.json()['id']}/content", headers=auth_headers)
    assert served.headers["content-type"].startswith("text/plain") and served.headers["content-disposition"].startswith("attachment")

    fake = await _upload(client, auth_headers, fid, b"MZ\x90\x00\x03\x00\x00\x00", name="totally-a.png")
    assert fake.status_code == 415
    zipped = await _upload(client, auth_headers, fid, b"PK\x03\x04\x14\x00\x00\x00", name="a.zip")
    assert zipped.status_code == 415
    pdf = await _upload(client, auth_headers, fid, b"%PDF-1.7\n%...", name="report.pdf")
    assert pdf.json()["content_type"] == "application/pdf"
    assert (await _upload(client, auth_headers, fid, b"")).status_code == 400


@pytest.mark.asyncio
async def test_size_limit(client, auth_headers, monkeypatch):
    from scanr.config import get_settings

    monkeypatch.setattr(get_settings(), "evidence_max_mb", 1)
    _, fid = await _finding(client, auth_headers)
    r = await _upload(client, auth_headers, fid, b"a" * (1024 * 1024 + 1), name="big.txt")
    assert r.status_code == 413


@pytest.mark.asyncio
async def test_other_users_and_viewers(client, auth_headers):
    _, fid = await _finding(client, auth_headers)
    att = (await _upload(client, auth_headers, fid, tiny_png())).json()
    email = f"ev-viewer-{uuid.uuid4().hex[:6]}@scanr.local"
    await client.post("/api/v1/users", json={"email": email, "password": "long-enough-pw", "role": "viewer"}, headers=auth_headers)
    login = await client.post("/api/v1/auth/login", json={"email": email, "password": "long-enough-pw"})
    other = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.get(f"/api/v1/attachments/{att['id']}/content", headers=other)).status_code == 404
    assert (await client.get(f"/api/v1/findings/{fid}/attachments", headers=other)).status_code == 404
    assert (await _upload(client, other, fid, tiny_png())).status_code == 403
    assert (await client.delete(f"/api/v1/attachments/{att['id']}", headers=other)).status_code == 403


@pytest.mark.asyncio
async def test_deleting_the_scan_removes_rows_and_cleanup_removes_files(client, auth_headers, evidence_dir):
    scan_id, fid = await _finding(client, auth_headers)
    att = (await _upload(client, auth_headers, fid, tiny_png())).json()
    assert (await client.delete(f"/api/v1/scans/{scan_id}", headers=auth_headers)).status_code == 204
    assert (await client.get(f"/api/v1/attachments/{att['id']}/content", headers=auth_headers)).status_code == 404

    from scanr.core.maintenance import remove_orphaned_evidence

    assert (evidence_dir / fid / att["id"]).exists()
    assert await remove_orphaned_evidence() >= 1
    assert not (evidence_dir / fid).exists()
