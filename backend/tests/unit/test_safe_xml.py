"""Imported scanner reports are untrusted XML.

ElementTree blocks external entity *resolution* but still expands entities a
document declares in its own internal DTD subset, so a few kilobytes of nested
declarations can expand to gigabytes and take the worker down with it.
"""
import xml.etree.ElementTree as ET

import pytest

from scanr.utils.safe_xml import XmlSecurityError, fromstring

_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>"""

_XXE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE f [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<f>&xxe;</f>"
)


def test_entity_expansion_bomb_is_refused():
    with pytest.raises(XmlSecurityError):
        fromstring(_BILLION_LAUGHS)


def test_external_entity_is_refused():
    with pytest.raises(XmlSecurityError):
        fromstring(_XXE)


def test_bomb_is_refused_before_it_can_expand():
    """The guard must reject on the declaration, not after building the string."""
    import time

    start = time.monotonic()
    with pytest.raises(XmlSecurityError):
        fromstring(_BILLION_LAUGHS)
    assert time.monotonic() - start < 1.0


def test_ordinary_burp_shaped_report_still_parses():
    root = fromstring(
        "<issues><item><type>XSS</type><severity>High</severity></item></issues>"
    )
    items = root.findall(".//item")
    assert [i.findtext("type") for i in items] == ["XSS"]


def test_doctype_without_entities_still_parses():
    """nmap and friends declare a DOCTYPE but no entities."""
    doc = '<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host/></nmaprun>'
    assert fromstring(doc).tag == "nmaprun"


def test_literal_entity_text_in_content_is_not_a_declaration():
    """A report quoting "<!ENTITY ...>" as data must not be mistaken for one."""
    doc = (
        "<issues><item><detail><![CDATA[example: <!ENTITY foo \"bar\">]]>"
        "</detail></item></issues>"
    )
    assert "<!ENTITY" in fromstring(doc).findtext(".//detail")


def test_malformed_xml_still_raises_parse_error():
    """Callers distinguish "hostile" from "merely broken"."""
    with pytest.raises(ET.ParseError):
        fromstring("<a><b></a>")


def test_accepts_bytes_and_str():
    assert fromstring(b"<a>1</a>").tag == "a"
    assert fromstring("<a>1</a>").tag == "a"
