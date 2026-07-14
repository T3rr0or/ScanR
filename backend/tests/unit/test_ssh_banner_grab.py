"""Unit tests for the SSH-on-any-port fallback (pure banner analysis)."""
from scanr.plugins.services.ssh_banner_grab import SshBannerGrabPlugin


def test_non_ssh_or_empty_banner_yields_nothing():
    p = SshBannerGrabPlugin()
    assert p._findings_for("192.0.2.1", 2022, None) == []
    assert p._findings_for("192.0.2.1", 2022, "220 ProFTPD 1.3 Server ready") == []
    assert p._findings_for("192.0.2.1", 2022, "HTTP/1.1 400 Bad Request") == []


def test_modern_ssh_reports_exposure_only():
    p = SshBannerGrabPlugin()
    fs = p._findings_for("192.0.2.1", 2022, "SSH-2.0-OpenSSH_9.9")
    assert len(fs) == 1
    assert "Non-Standard Port 2022" in fs[0].title
    assert fs[0].port_number == 2022
    assert "SSH-2.0-OpenSSH_9.9" in fs[0].evidence


def test_vulnerable_ssh_adds_version_finding():
    p = SshBannerGrabPlugin()
    fs = p._findings_for("192.0.2.1", 2022, "SSH-2.0-OpenSSH_6.6")
    # detection finding + the reused version-vulnerability finding
    assert len(fs) >= 2
    assert any("Non-Standard Port" in f.title for f in fs)
    assert any(f.cve_ids for f in fs)
    # every finding is attributed to this plugin, not ssh.ssh_version
    assert all(f.plugin_id == "services.ssh_banner_grab" for f in fs)
