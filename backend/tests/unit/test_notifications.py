import json

import pytest

from scanr.core import notifications as n
from scanr.models.notification_channel import NotificationChannel


@pytest.mark.parametrize("kind,target", [
    ("slack", "https://hooks.slack.com/services/T0/B0/xyz"),
    ("teams", "https://contoso.webhook.office.com/webhookb2/abc"),
    ("teams", "https://prod-12.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x"),
    ("email", "  soc@example.com "),
])
def test_valid_targets(kind, target):
    assert n.validate_target(kind, target) == target.strip()


@pytest.mark.parametrize("kind,target", [
    ("slack", "http://hooks.slack.com/services/x"),
    ("slack", "https://hooks.slack.com.evil.example/x"),
    ("teams", "https://evil.example/webhook.office.com"),
    ("teams", "https://webhook.office.com.evil.example/x"),
    ("email", "a@b.com, c@d.com"),
    ("email", "victim@example.com\r\nBcc: x@y.z"),
    ("email", "not-an-address"),
])
def test_invalid_targets(kind, target):
    with pytest.raises(ValueError):
        n.validate_target(kind, target)


def _summary(**kw):
    s = n.sample_summary()
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def test_text_and_html_rendering_escape_and_include_link(monkeypatch):
    summary = _summary(top=[n.TopFinding("<script>x</script> & co", "10.0.0.1:80", "high", 85, True, ["internet-facing host"])])
    assert "1 to fix now" in summary.headline
    text = n.render_text(summary)
    assert "[85 KEV] <script>x</script> & co (10.0.0.1:80) — internet-facing host" in text
    assert "Open ScanR: http://" in text
    html = n.render_html(summary)
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_slack_payload_escapes_markup():
    payload = n.slack_payload(_summary(top=[n.TopFinding("<!channel> a&b", "h", "high", 50, False, [])]))
    text = payload["blocks"][0]["text"]["text"]
    assert "&lt;!channel&gt; a&amp;b" in text and "<!channel>" not in text
    assert text.endswith("|Open ScanR>")


def test_teams_payload_is_an_adaptive_card():
    payload = n.teams_payload(n.sample_summary())
    card = payload["attachments"][0]["content"]
    assert payload["type"] == "message" and card["type"] == "AdaptiveCard"
    assert card["body"][2]["facts"][0]["title"] == "91 KEV"
    failed = n.teams_payload(_summary(status="failed", error="nmap crashed"))
    assert "nmap crashed" in json.dumps(failed)


def _channel(events, min_priority=None):
    return NotificationChannel(kind="slack", events=json.dumps(events), min_priority=min_priority, enabled=True)


def test_wants_filters_on_event_and_priority():
    summary = _summary(max_priority=65)
    assert n.wants(_channel(["scan.completed"]), "scan.completed", summary)
    assert not n.wants(_channel(["scan.failed"]), "scan.completed", summary)
    assert n.wants(_channel(["scan.completed"], 60), "scan.completed", summary)
    assert not n.wants(_channel(["scan.completed"], 80), "scan.completed", summary)
    assert not n.wants(_channel(["scan.completed"], 10), "scan.completed", _summary(max_priority=None))
    # Failures are always worth hearing about, whatever the threshold.
    assert n.wants(_channel(["scan.failed"], 80), "scan.failed", _summary(status="failed"))


def test_email_via_smtp(monkeypatch):
    from scanr.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "smtp_host", "mail.example.com")
    monkeypatch.setattr(settings, "smtp_from", "scanr@example.com")
    monkeypatch.setattr(settings, "smtp_username", "user")
    monkeypatch.setattr(settings, "smtp_password", "pw")
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["server"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context):
            sent["tls"] = True

        def login(self, user, password):
            sent["login"] = user

        def send_message(self, message):
            sent["message"] = message

    monkeypatch.setattr(n.smtplib, "SMTP", FakeSMTP)
    n._send_email_sync("soc@example.com", "Subject", "text body", "<p>html</p>")
    msg = sent["message"]
    assert sent["server"] == ("mail.example.com", 587) and sent["tls"] and sent["login"] == "user"
    assert msg["To"] == "soc@example.com" and msg["From"] == "scanr@example.com"
    assert msg.get_body(("plain",)).get_content().strip() == "text body"


def test_email_requires_configuration(monkeypatch):
    from scanr.config import get_settings

    monkeypatch.setattr(get_settings(), "smtp_host", "")
    with pytest.raises(n.NotificationError, match="not configured"):
        n._send_email_sync("a@b.co", "s", "t", "h")
