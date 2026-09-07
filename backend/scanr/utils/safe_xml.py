"""Entity-expansion-safe XML parsing for untrusted documents.

`xml.etree.ElementTree` blocks external entity *resolution*, but it happily
expands entities declared in a document's own internal DTD subset. That is all a
"billion laughs" attack needs: a few kilobytes of nested entity declarations
expand to gigabytes during parsing and exhaust the worker process.

`ElementTree.XMLParser` no longer exposes the underlying expat parser, so the
declarations are rejected in a separate expat pass that stops at the root
element — the internal DTD subset, if any, is fully seen by then, and no entity
reference in the document body has been expanded yet. Well-formed scanner
reports (Burp, ZAP, nmap) describe findings with elements and attributes, not
custom entities, so a document that declares one is treated as hostile.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.parsers import expat

__all__ = ["XmlSecurityError", "fromstring"]


class XmlSecurityError(ValueError):
    """Raised when a document uses XML features we refuse to parse."""


class _ReachedRootElement(Exception):
    """Internal signal: the prologue is parsed, nothing hostile was declared."""


def _reject_entity_declarations(text: bytes) -> None:
    """Raise `XmlSecurityError` if the document's prologue declares any entity."""
    parser = expat.ParserCreate()

    def _on_entity_decl(*_args: object, **_kwargs: object) -> None:
        raise XmlSecurityError("XML entity declarations are not permitted")

    def _on_external_entity(*_args: object, **_kwargs: object) -> bool:
        raise XmlSecurityError("XML external entities are not permitted")

    def _on_start_element(*_args: object, **_kwargs: object) -> None:
        raise _ReachedRootElement

    parser.EntityDeclHandler = _on_entity_decl
    parser.UnparsedEntityDeclHandler = _on_entity_decl
    parser.ExternalEntityRefHandler = _on_external_entity
    parser.StartElementHandler = _on_start_element

    try:
        parser.Parse(text, True)
    except _ReachedRootElement:
        pass
    except expat.ExpatError:
        # Malformed input: let the real parse below raise ET.ParseError, so
        # callers see one consistent error type for bad XML.
        pass


def fromstring(text: str | bytes) -> ET.Element:
    """Parse `text` into an element tree, refusing entity-expansion payloads.

    Raises `XmlSecurityError` for documents that declare entities, and the usual
    `ET.ParseError` for documents that are merely malformed.
    """
    raw = text.encode("utf-8", errors="ignore") if isinstance(text, str) else text
    _reject_entity_declarations(raw)
    return ET.fromstring(text)
