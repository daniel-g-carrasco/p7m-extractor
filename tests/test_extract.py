#!/usr/bin/env python3
"""Standalone tests for the P7M extraction core (no external deps).

Run:  python tests/test_extract.py
Also used by CI to generate a smoke-test sample:
      python tests/test_extract.py --make-sample out.p7m
"""

import base64
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import p7m_extractor as px  # noqa: E402

# --- tiny BER builders ------------------------------------------------------

OID_SIGNED = bytes.fromhex("06092A864886F70D010702")
OID_DATA = bytes.fromhex("06092A864886F70D010701")


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def indef(tag: int, *parts: bytes) -> bytes:
    return bytes([tag, 0x80]) + b"".join(parts) + b"\x00\x00"


def p7m_definite(payload: bytes) -> bytes:
    """Plain DER SignedData with a single primitive OCTET STRING eContent."""
    encap = tlv(0x30, OID_DATA + tlv(0xA0, tlv(0x04, payload)))
    signed = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x31, b"") + encap)
    return tlv(0x30, OID_SIGNED + tlv(0xA0, signed))


def p7m_streaming(payload: bytes, chunk: int = 1000) -> bytes:
    """BER indefinite-length SignedData with chunked constructed OCTET STRING,
    as produced by common Italian signing software."""
    chunks = [tlv(0x04, payload[i:i + chunk])
              for i in range(0, len(payload), chunk)] or [tlv(0x04, b"")]
    encap = indef(0x30, OID_DATA, indef(0xA0, indef(0x24, *chunks)))
    signed = indef(0x30, tlv(0x02, b"\x01"), tlv(0x31, b""), encap)
    return indef(0x30, OID_SIGNED, indef(0xA0, signed))


def p7m_detached() -> bytes:
    encap = tlv(0x30, OID_DATA)  # no [0] eContent
    signed = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x31, b"") + encap)
    return tlv(0x30, OID_SIGNED + tlv(0xA0, signed))


# binary payload exercising every byte value, including \n and \x00
PAYLOAD = (b"%PDF-1.7 fake\n" + bytes(range(256)) * 40 + b"\n%%EOF\n")


def expect_raises(exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc:
        return
    raise AssertionError(f"{fn.__name__} did not raise {exc.__name__}")


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--make-sample":
        Path(sys.argv[2]).write_bytes(p7m_streaming(PAYLOAD))
        print(f"sample written: {sys.argv[2]}")
        return 0

    # core: definite DER
    assert px.extract_econtent(p7m_definite(PAYLOAD)) == PAYLOAD
    # core: BER streaming with 1000-byte chunks
    assert px.extract_econtent(p7m_streaming(PAYLOAD)) == PAYLOAD
    # container: bare base64 and PEM
    assert px.decode_container(
        base64.encodebytes(p7m_definite(PAYLOAD))) == p7m_definite(PAYLOAD)
    pem = (b"-----BEGIN PKCS7-----\n"
           + base64.encodebytes(p7m_streaming(PAYLOAD))
           + b"-----END PKCS7-----\n")
    assert px.extract_econtent(px.decode_container(pem)) == PAYLOAD
    # errors: detached and garbage
    expect_raises(px.BerError, px.extract_econtent, p7m_detached())
    expect_raises(px.BerError, px.extract_econtent, b"%PDF-1.4 not signed")
    expect_raises(px.BerError, px.extract_econtent, p7m_definite(PAYLOAD)[:50])

    # file-level: naming, nested envelopes, skip/overwrite
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        f = td / "doc.pdf.p7m"
        f.write_bytes(p7m_streaming(PAYLOAD))
        dest, layers = px.extract_file(f)
        assert dest == td / "doc.pdf" and layers == 1
        assert dest.read_bytes() == PAYLOAD

        nested = td / "doppia.pdf.p7m.p7m"
        nested.write_bytes(p7m_definite(p7m_streaming(PAYLOAD)))
        dest, layers = px.extract_file(nested)
        assert dest == td / "doppia.pdf" and layers == 2
        assert dest.read_bytes() == PAYLOAD

        expect_raises(FileExistsError, px.extract_file, f)
        dest, _ = px.extract_file(f, overwrite=True)
        assert dest.read_bytes() == PAYLOAD

        # folder scan finds .p7m case-insensitively, recursively
        (td / "sub").mkdir()
        upper = td / "sub" / "UPPER.XML.P7M"
        upper.write_bytes(p7m_definite(b"<xml/>"))
        found = px.iter_p7m([td])
        assert upper in found and f in found and nested in found

    print("all tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
