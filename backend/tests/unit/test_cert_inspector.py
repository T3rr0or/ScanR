"""Unit tests for the certificate inspector — parses real generated DER certs
(the plugin previously read an empty getpeercert() dict and found nothing)."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scanr.plugins.ssl_tls.cert_inspector import CertInspectorPlugin, _host_matches

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert(cn="example.com", sans=("example.com",), not_after_days=365, hash_alg=None, self_signed=True) -> bytes:
    hash_alg = hash_alg or hashes.SHA256()
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=40))
        .not_valid_after(now + timedelta(days=not_after_days))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(_KEY, hash_alg)
    return cert.public_bytes(serialization.Encoding.DER)


def _titles(der, hostname):
    return [f.title for f in CertInspectorPlugin()._analyze_cert(der, hostname, 443)]


def test_host_matches_wildcards():
    assert _host_matches("a.example.com", {"*.example.com"})
    assert not _host_matches("example.com", {"*.example.com"})       # wildcard needs a label
    assert not _host_matches("a.b.example.com", {"*.example.com"})   # only one label
    assert _host_matches("example.com", {"example.com"})
    assert not _host_matches("evil.com", {"example.com", "*.example.com"})


def test_self_signed_valid_matching():
    titles = _titles(_cert(), "example.com")
    assert any("Self-Signed" in t for t in titles)
    assert not any("Mismatch" in t or "Expir" in t for t in titles)


def test_hostname_mismatch():
    titles = _titles(_cert(cn="example.com", sans=("example.com",)), "other.com")
    assert any("Hostname Mismatch" in t for t in titles)


def test_expired():
    titles = _titles(_cert(not_after_days=-5), "example.com")
    assert any("Expired" in t for t in titles)


def test_ca_signed_valid_matching_is_clean():
    # trusted-looking (not self-signed), valid, name matches → no findings
    titles = _titles(_cert(self_signed=False), "example.com")
    assert titles == []
