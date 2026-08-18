"""The CLI must verify TLS certificates when talking to the ScanR API.

Every CLI request carries an API key in the Authorization header, so an
unverified connection hands that credential to anyone able to intercept the
route. For `scanr ci` it is worse: the pass/fail verdict a pipeline gates on
becomes forgeable. Verification is therefore on by default and only an explicit
--insecure turns it off.

Note this is about the connection to the *API*. Plugins scanning targets
deliberately keep verify=False — a scanner has to reach hosts with broken certs.
"""
import httpx
import pytest
from click.testing import CliRunner

from scanr.cli.main import _verify, cli


@pytest.mark.parametrize("obj,expected", [
    ({}, True),                      # nothing set — must default to verifying
    ({"verify": True}, True),
    ({"verify": False}, False),
])
def test_verify_defaults_to_on(obj, expected):
    ctx = type("Ctx", (), {"obj": obj})()
    assert _verify(ctx) is expected


def _capture_verify(monkeypatch) -> list:
    """Record the verify= argument of every httpx call the CLI makes."""
    seen: list = []

    def fake_request(method, url, **kwargs):
        seen.append(kwargs.get("verify"))
        return httpx.Response(200, json={"access_token": "t"}, request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "request", fake_request)
    return seen


def test_api_calls_verify_by_default(monkeypatch):
    seen = _capture_verify(monkeypatch)
    CliRunner().invoke(
        cli,
        ["--url", "https://scanr.test", "login",
         "--email", "a@b.c", "--password", "secret1234"],
    )
    assert seen, "no HTTP call was made"
    assert all(v is True for v in seen), f"expected TLS verification on, got {seen}"


def test_insecure_flag_opts_out(monkeypatch):
    seen = _capture_verify(monkeypatch)
    CliRunner().invoke(
        cli,
        ["--url", "https://scanr.test", "--insecure", "login",
         "--email", "a@b.c", "--password", "secret1234"],
    )
    assert seen, "no HTTP call was made"
    assert all(v is False for v in seen), f"expected verification off, got {seen}"


def test_insecure_over_https_warns_the_operator(monkeypatch):
    _capture_verify(monkeypatch)
    result = CliRunner().invoke(
        cli,
        ["--url", "https://scanr.test", "--insecure", "login",
         "--email", "a@b.c", "--password", "secret1234"],
    )
    assert "verification disabled" in result.output.lower()


def test_no_verify_false_literals_remain_in_the_cli():
    """The CLI talks only to the ScanR API, so a hardcoded opt-out is always wrong
    here — even though plugins legitimately use verify=False against targets."""
    import pathlib

    import scanr.cli.main as cli_module

    source = pathlib.Path(cli_module.__file__).read_text()
    assert "verify=False" not in source
