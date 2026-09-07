"""Finding evidence must prove IMDS exposure without copying the credentials.

Evidence is persisted to the findings table and rendered into reports, the API
and the UI — all outside the credential vault. Echoing the IMDS credential
document there creates a second, less-guarded store of live cloud keys.
"""
from scanr.plugins.web.aws_metadata_ssrf import _CREDENTIAL_FIELDS, _credential_fields

_IMDS_RESPONSE = """{
  "Code" : "Success",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token" : "IQoJb3JpZ2luX2VjEO3//////////wEaCXVzLWVhc3QtMSJHMEUCIQ",
  "Expiration" : "2026-09-07T21:00:00Z"
}"""


def test_names_the_fields_present():
    summary = _credential_fields(_IMDS_RESPONSE)
    for field in _CREDENTIAL_FIELDS:
        assert field in summary


def test_never_returns_the_secret_values():
    summary = _credential_fields(_IMDS_RESPONSE)
    for secret in (
        "ASIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "IQoJb3JpZ2luX2VjEO3//////////wEaCXVzLWVhc3QtMSJHMEUCIQ",
    ):
        assert secret not in summary


def test_unrecognised_body_is_reported_as_such():
    assert _credential_fields("not json at all") == "unrecognised response shape"
    assert _credential_fields("") == "unrecognised response shape"


def test_partial_document_names_only_what_is_there():
    summary = _credential_fields('{"Code":"Success","AccessKeyId":"AKIA"}')
    assert "AccessKeyId" in summary and "Code" in summary
    assert "SecretAccessKey" not in summary
    assert "AKIA" not in summary
