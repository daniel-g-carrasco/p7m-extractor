"""The .p7m container: a PKCS#7/CMS SignedData envelope read as BER/DER with
the standard library only, and the document inside it taken out as it was
signed. Bytes in, bytes out: no file is opened here.
"""

from __future__ import annotations

import base64
import binascii
import re

OID_SIGNED_DATA = bytes.fromhex("2A864886F70D010702")  # 1.2.840.113549.1.7.2
OID_DATA = bytes.fromhex("2A864886F70D010701")         # 1.2.840.113549.1.7.1


class BerError(ValueError):
    """Raised when the input is not a (supported) PKCS#7 SignedData blob."""


def _read_header(data: bytes, i: int):
    """Parse a BER TLV header. Return (tag, constructed, length, content_start).

    length is None for indefinite-length encodings (BER streaming).
    """
    tag = data[i]
    constructed = bool(tag & 0x20)
    i += 1
    if tag & 0x1F == 0x1F:  # high tag number form
        while data[i] & 0x80:
            i += 1
        i += 1
    length = data[i]
    i += 1
    if length == 0x80:
        if not constructed:
            raise BerError("indefinite length on a primitive element")
        return tag, constructed, None, i
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 8:
            raise BerError("unsupported length-of-length")
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    return tag, constructed, length, i


def _end_of(data: bytes, i: int) -> int:
    """Index just past the TLV starting at i (EOC included if indefinite)."""
    _tag, _cons, length, cs = _read_header(data, i)
    if length is not None:
        return cs + length
    j = cs
    while data[j:j + 2] != b"\x00\x00":
        j = _end_of(data, j)
    return j + 2


def _node(data: bytes, i: int):
    """Return (tag, constructed, content_start, content_end, next_index)."""
    tag, cons, length, cs = _read_header(data, i)
    nxt = _end_of(data, i)
    ce = cs + length if length is not None else nxt - 2
    return tag, cons, cs, ce, nxt


def _children(data: bytes, start: int, end: int):
    i = start
    while i < end:
        node = _node(data, i)
        yield node
        i = node[4]


def _collect_octets(data: bytes, start: int, end: int, out: list) -> None:
    """Concatenate every OCTET STRING found under [start, end)."""
    for tag, cons, cs, ce, _nxt in _children(data, start, end):
        if tag & 0xDF == 0x04:  # OCTET STRING, primitive (0x04) or constructed (0x24)
            if cons:
                _collect_octets(data, cs, ce, out)
            else:
                out.append(data[cs:ce])
        else:
            raise BerError(f"unexpected element {tag:#04x} inside eContent")


def extract_econtent(der: bytes) -> bytes:
    """Return the encapsulated content of a BER/DER PKCS#7 SignedData blob."""
    try:
        tag, cons, cs, ce, _next = _node(der, 0)
        if tag != 0x30 or not cons:
            raise BerError("not a PKCS#7/CMS structure")
        kids = list(_children(der, cs, ce))
        if not kids or kids[0][0] != 0x06:
            raise BerError("missing content-type OID")
        ctype = der[kids[0][2]:kids[0][3]]
        if ctype != OID_SIGNED_DATA:
            raise BerError("not a signedData envelope")
        wrapper = next((k for k in kids if k[0] == 0xA0), None)
        if wrapper is None:
            raise BerError("missing signedData body")
        sd = _node(der, wrapper[2])
        if sd[0] != 0x30:
            raise BerError("malformed SignedData")
        # SignedData children: INTEGER version, SET digestAlgorithms,
        # SEQUENCE encapContentInfo, [certificates], [crls], SET signerInfos.
        enc = next((k for k in _children(der, sd[2], sd[3]) if k[0] == 0x30), None)
        if enc is None:
            raise BerError("missing encapContentInfo")
        e0 = next((k for k in _children(der, enc[2], enc[3]) if k[0] == 0xA0), None)
        if e0 is None:
            raise BerError("detached signature: the signed content is not embedded")
        out: list = []
        _collect_octets(der, e0[2], e0[3], out)
        content = b"".join(out)
        if not content:
            raise BerError("empty signed content")
        return content
    except IndexError:
        raise BerError("truncated structure") from None
    except RecursionError:
        raise BerError("structure nested too deeply") from None


_B64_RE = re.compile(rb"[A-Za-z0-9+/=]+\Z")


def decode_container(raw: bytes) -> bytes:
    """Return DER/BER bytes from raw file content (handles PEM and bare base64)."""
    s = raw.lstrip()
    if s.startswith(b"-----BEGIN"):
        body = b"".join(
            line.strip() for line in s.splitlines()
            if line.strip() and not line.strip().startswith(b"-----")
        )
        try:
            return base64.b64decode(body, validate=True)
        except binascii.Error as e:
            raise BerError(f"invalid PEM base64: {e}") from None
    if raw[:1] == b"\x30":
        return raw
    compact = b"".join(raw.split())
    if compact[:2] == b"MI" and _B64_RE.fullmatch(compact):
        # DER starts with 0x30 0x8x, which is "MI..." once base64-encoded.
        try:
            return base64.b64decode(compact, validate=True)
        except binascii.Error:
            pass
    return raw
